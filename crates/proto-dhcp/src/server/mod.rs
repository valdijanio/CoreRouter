//! The DHCPv4 server (G4.2a), pure: no socket, no clock, no disk. The
//! engine feeds it what the interfaces heard and the time, and carries out
//! what it asks for ([`Effect`]): send a reply, probe an address, write a
//! journal line, name a lease in the DNS, log.
//!
//! What it follows, by section of RFC 2131:
//!
//! - §4.2: a client is its client identifier (option 61) when it sends
//!   one, else its `chaddr`; RFC 4361 §6.3: a static lease written by MAC
//!   still matches it.
//! - §4.3.1: the address offered is, in order, the client's static lease,
//!   its current binding, its previous address, the one it asks for
//!   (option 50), then the next never-used address of the pool (and of its
//!   `next_pool`s), then the free address idle the longest. An address on
//!   offer is held for [`OFFER_HOLD`] (RouterOS 7.16: 120 s).
//! - §3.1 step 2, §2.2: a new address is probed (ARP) before it is offered,
//!   when `conflict_detection` is on: the OFFER waits [`PROBE_WAIT_MS`]
//!   (as Kea's ping-check parks it); an address someone answers for is
//!   marked `conflict` for the lease time and another is tried. Static
//!   leases and a client's own address are not probed (RouterOS).
//! - §4.3.2: REQUEST in SELECTING (ours: ACK or NAK; another server's: the
//!   offer is freed), INIT-REBOOT and RENEWING/REBINDING; `authoritative`
//!   decides between NAK and silence for addresses the server does not
//!   know (after its `secs` delay). An authoritative server ACKs a known-free
//!   address it has no record of (dnsmasq's `dhcp-authoritative`): the
//!   clients rebuild a lost lease table without renumbering.
//! - §4.3.3 DECLINE (the address is held `declined`), §4.3.4 RELEASE (the
//!   record stays, so the client gets the address back), §4.3.5 INFORM.
//! - §4.1: where replies go; §4.4.5: T1 = 0.5 × lease, T2 = 0.875 × lease.
//! - RFC 6842 §3: option 61 echoed; RFC 3046 §2.2: option 82 echoed, last;
//!   RFC 4702 §4: option 81 answered with the S/O/N flags; the DNS is
//!   updated on ACK only, never on DISCOVER (§4.1).

pub mod agent;
pub mod authorize;
pub mod checks;
pub mod history;
pub mod leases;
pub mod plan;
pub mod reply;
pub mod request;
pub mod stats;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;

use corerouter_hal::dhcp_server::{Heard, ReplyTo};
use corerouter_model::IfName;

use leases::{Lease, Leases, Record, State};
use plan::{OptPlan, Plan, ServerPlan, StaticPlan};
use request::{Bad, FQDN_E, FQDN_N, FQDN_O, FQDN_S, Kind, Request};
use stats::{Drop, Stats};

/// Seconds an offered address is held for its client (RouterOS 7.16).
pub const OFFER_HOLD: u64 = 120;
/// How long an OFFER waits for an answer to its ARP probe (RouterOS ~0.5 s;
/// Cisco's default ping timeout).
pub const PROBE_WAIT_MS: u64 = 500;
/// Addresses probed for one DISCOVER before giving up (the client asks
/// again).
pub const PROBE_TRIES: usize = 3;
/// How long a free address remembers its last client (RFC 2131 §4.3.1
/// affinity; Kea's `hold-reclaimed-time` is an hour, a weekend away is
/// more useful: **estimado**).
pub const KEEP_FREE_SECS: u64 = 7 * 86_400;
/// How often an alert sends its own DISCOVER (RouterOS: once a minute).
pub const ALERT_PROBE_SECS: u64 = 60;
/// Offers waiting for a probe at once (a DISCOVER flood is bounded here).
pub const MAX_PARKED: usize = 4096;
/// A full pool is logged at most this often (a random-MAC flood on a full
/// pool would write one warning per DISCOVER).
pub const FULL_LOG_SECS: u64 = 60;
/// Clients the rate limiter remembers (random-MAC floods are bounded).
pub const MAX_CLIENTS_TRACKED: usize = 65_536;
/// A full rate-limit table is swept for clients that are full again at
/// most this often.
pub const SWEEP_MS: u64 = 250;
/// An address whose probe came back clean is offered again without a
/// probe within this time (a client retrying its DISCOVER).
const PROBED_OK_MS: u64 = 60_000;
/// The DNS TTL of a lease's records: a third of the lease, at least 600 s
/// (RFC 4702 §5, Kea).
pub fn dns_ttl(lease_time: u32) -> u32 {
    (lease_time / 3).max(600)
}

/// The DISCOVER an alert sends from `mac` (broadcast reply asked for: a
/// rogue server's answer reaches every listener).
pub fn alert_discover(mac: [u8; 6], xid: u32) -> Option<Vec<u8>> {
    crate::v4::Outgoing {
        kind: dhcproto::v4::MessageType::Discover,
        xid,
        secs: 0,
        mac,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        broadcast: true,
        requested: None,
        server_id: None,
        client_id: &[],
        host_name: None,
        vendor_class: None,
        extra: &[],
    }
    .encode()
    .ok()
}

/// The two clocks: monotonic milliseconds (probes, rate limits) and Unix
/// seconds (leases, which outlive a restart).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Now {
    pub ms: u64,
    pub unix: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Info,
    Warning,
    /// RouterOS logs a rogue server under `dhcp,critical`.
    Critical,
}

/// What a bound lease means outside the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub lease: Lease,
    /// A new binding (not a renewal of the same client's).
    pub new: bool,
    /// `<label>.<zone>` when the network names a zone and the client a
    /// name (and did not ask for no update, RFC 4702 N).
    pub dns: Option<(String, String)>,
    pub ttl: u32,
    pub address_lists: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    Send {
        interface: IfName,
        payload: Vec<u8>,
        src: Ipv4Addr,
        to: ReplyTo,
        kind: Kind,
    },
    Probe {
        interface: IfName,
        ip: Ipv4Addr,
        src: Ipv4Addr,
    },
    /// A lease was bound (or renewed).
    Bound(Binding),
    /// A lease ended (released, expired, declined, its server removed).
    Gone(Lease),
    /// A journal line to write before any reply of this round goes out.
    Journal(Record),
    /// Send our own DISCOVER on `interface` (an alert looks for servers
    /// that only answer by unicast, as RouterOS does once a minute).
    Discover {
        interface: IfName,
    },
    /// Ask whether this client may be served (IPoE, G4.3f): the answer
    /// comes back through [`Server::authorized`].
    Authorize(authorize::AuthAsk),
    Log {
        level: Level,
        text: String,
    },
}

/// An OFFER waiting for its probe.
#[derive(Debug, Clone)]
struct Parked {
    interface: IfName,
    server: String,
    req: Request,
    ip: Ipv4Addr,
    deadline_ms: u64,
    tried: Vec<Ipv4Addr>,
    matcher_pool: Option<String>,
}

/// Token bucket per client MAC (milli-messages).
#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: u64,
    at_ms: u64,
}

/// A server heard where an alert watches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen {
    pub interface: IfName,
    pub mac: [u8; 6],
    pub ip: Ipv4Addr,
    pub server_id: Option<Ipv4Addr>,
    pub first: u64,
    pub last: u64,
    pub count: u64,
    /// When it was last logged (a new alert after `alert_timeout`).
    alerted: u64,
}

/// Use of one pool.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PoolUse {
    pub pool: String,
    pub size: u64,
    pub bound: u64,
    pub offered: u64,
    pub held: u64,
}

impl PoolUse {
    /// Percent of the pool bound or on offer.
    pub fn percent(&self) -> u64 {
        (self.bound + self.offered)
            .saturating_mul(100)
            .checked_div(self.size)
            .unwrap_or(0)
    }
}

#[derive(Clone)]
pub struct Server {
    plan: Plan,
    leases: Leases,
    parked: Vec<Parked>,
    /// (server, client) of each parked offer: a retransmitted DISCOVER
    /// is found in O(1) (a storm parks thousands).
    parked_keys: HashSet<(String, Vec<u8>)>,
    probed_ok: HashMap<Ipv4Addr, u64>,
    /// Conflicts being checked again (`check-status`): address → deadline.
    checking: HashMap<Ipv4Addr, (IfName, u64)>,
    limiter: HashMap<[u8; 6], Bucket>,
    /// When the full limiter was last swept.
    limiter_swept_ms: u64,
    stats: Stats,
    seen: BTreeMap<(IfName, [u8; 6]), Seen>,
    /// Next offset to try per pool.
    cursor: HashMap<String, u64>,
    /// Pools known to have no never-used address, at generation `gen`.
    exhausted: HashMap<String, u64>,
    /// Moves when the plan changes or a record goes (an address may be
    /// never-used again).
    generation: u64,
    last_tick: u64,
    /// Option 82 of the client being handled (its request's, or the one
    /// its lease kept: a renewal comes straight, without the relay).
    agent: Option<Vec<u8>>,
    /// Last DISCOVER sent per alert interface (Unix time).
    alert_probe: HashMap<IfName, u64>,
    /// When "pool is full" was last logged, per (server, pool).
    full_logged: HashMap<(String, String), u64>,
    /// Clients asked about, granted and refused (IPoE, G4.3f).
    gate: authorize::Gate,
}

fn mac_text(m: &[u8; 6]) -> String {
    let [a, b, c, d, e, f] = *m;
    format!("{a:02X}:{b:02X}:{c:02X}:{d:02X}:{e:02X}:{f:02X}")
}

/// A DNS label from what a client calls itself: lowercase letters, digits
/// and `-`, at most 63, no `-` at the ends.
pub fn dns_label(name: &str) -> String {
    let first = name.split('.').next().unwrap_or("");
    let s: String = first
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .take(63)
        .collect();
    s.trim_matches('-').to_owned()
}

/// The `n`th address of `ranges` (in order).
fn nth(ranges: &[corerouter_model::ip_pool::PoolRange], mut n: u64) -> Option<Ipv4Addr> {
    for r in ranges {
        if n < r.len() {
            let base = u64::from(u32::from(r.start));
            return u32::try_from(base + n).ok().map(Ipv4Addr::from);
        }
        n -= r.len();
    }
    None
}

impl Server {
    pub fn new(plan: Plan, now_unix: u64) -> Self {
        Self {
            plan,
            leases: Leases::default(),
            parked: Vec::new(),
            parked_keys: HashSet::new(),
            probed_ok: HashMap::new(),
            checking: HashMap::new(),
            limiter: HashMap::new(),
            limiter_swept_ms: 0,
            stats: Stats::new(now_unix),
            seen: BTreeMap::new(),
            cursor: HashMap::new(),
            exhausted: HashMap::new(),
            generation: 0,
            last_tick: 0,
            agent: None,
            alert_probe: HashMap::new(),
            full_logged: HashMap::new(),
            gate: authorize::Gate::default(),
        }
    }

    pub fn plan(&self) -> &Plan {
        &self.plan
    }

    pub fn leases(&self) -> &Leases {
        &self.leases
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub fn stats_mut(&mut self) -> &mut Stats {
        &mut self.stats
    }

    pub fn reset_stats(&mut self, now_unix: u64) {
        self.stats = Stats::new(now_unix);
    }

    pub fn seen(&self) -> impl Iterator<Item = &Seen> {
        self.seen.values()
    }

    /// Forget the servers seen on `iface` (RouterOS `reset-alert`).
    pub fn reset_alert(&mut self, iface: &IfName) -> usize {
        let before = self.seen.len();
        self.seen.retain(|(i, _), _| i != iface);
        before - self.seen.len()
    }

    /// Offers waiting for a probe, as (address, interface).
    pub fn testing(&self) -> Vec<(Ipv4Addr, IfName)> {
        self.parked
            .iter()
            .map(|p| (p.ip, p.interface.clone()))
            .collect()
    }

    /// Load the journal (at start, before any message).
    pub fn replay<'a>(&mut self, lines: impl Iterator<Item = &'a str>) -> usize {
        let bad = self.leases.replay(lines);
        self.generation += 1;
        bad
    }

    /// The compacted journal.
    pub fn compact(&self, now_unix: u64) -> String {
        self.leases.compact(now_unix, KEEP_FREE_SECS)
    }

    /// A new running config. Leases of servers that are gone end
    /// (RouterOS 7.2 removes them too).
    pub fn configure(&mut self, plan: Plan) -> Vec<Effect> {
        let mut out = Vec::new();
        let gone: Vec<Ipv4Addr> = self
            .leases
            .iter()
            .filter(|l| !plan.servers.iter().any(|s| s.name == l.server))
            .map(|l| l.address)
            .collect();
        for ip in gone {
            if let Some(l) = self.leases.remove(ip) {
                if l.state == State::Bound {
                    out.push(Effect::Gone(l.clone()));
                }
                out.push(Effect::Journal(Record::Forget { forget: ip }));
            }
        }
        self.parked
            .retain(|p| plan.servers.iter().any(|s| s.name == p.server));
        self.gate
            .keep(|name| plan.servers.iter().any(|s| s.name == name && s.authorize));
        self.parked_keys = self
            .parked
            .iter()
            .map(|p| (p.server.clone(), p.req.client_key()))
            .collect();
        self.plan = plan;
        self.generation += 1;
        self.exhausted.clear();
        out
    }

    fn server(&self, name: &str) -> Option<&ServerPlan> {
        self.plan.servers.iter().find(|s| s.name == name)
    }

    // ---- what the interfaces heard -------------------------------------

    /// One message heard on `iface`.
    pub fn handle(&mut self, now: Now, iface: &IfName, heard: &Heard) -> Vec<Effect> {
        let mut out = Vec::new();
        if !heard.to_server {
            self.observe(now, iface, heard, &mut out);
            return out;
        }
        let mut req = match request::parse(&heard.payload) {
            Ok(r) => r,
            // A reply to a relay (ours, G4.2b): not for the server.
            Err(Bad::Reply) => return out,
            Err(Bad::NoType) => {
                self.stats.drop(Drop::Bootp);
                return out;
            }
            Err(_) => {
                self.stats.drop(Drop::Malformed);
                return out;
            }
        };
        self.stats.got(req.kind);
        // A client renewing by unicast (`ciaddr`, no relay on the way: RFC
        // 2131 §4.4.5) belongs to the server of its lease, wherever it
        // arrives (a client behind a relay renews straight to us).
        let by_lease = (req.giaddr.is_unspecified() && !req.ciaddr.is_unspecified())
            .then(|| self.leases.get(req.ciaddr))
            .flatten()
            .filter(|l| l.client_key() == req.client_key())
            .and_then(|l| self.plan.servers.iter().position(|s| s.name == l.server));
        let Some(si) = by_lease.or_else(|| self.plan.server_for(iface, req.giaddr)) else {
            self.stats.drop(Drop::NoServer);
            return out;
        };
        let Some(srv) = self.plan.servers.get(si).cloned() else {
            self.stats.drop(Drop::NoServer);
            return out;
        };
        if !self.allow(&srv, req.mac(), now.ms) {
            self.stats.drop(Drop::RateLimited);
            return out;
        }
        // RFC 3046 §2.1, §5: option 82 is the relay agent's; one that came
        // without a relay (giaddr 0) is the client's own unless an L2 agent
        // on this link is trusted to add it. Believed, it would pick another
        // subscriber's static lease and write their circuit in the history.
        if req.giaddr.is_unspecified() && !srv.relay_info_trusted && req.relay_info.is_some() {
            req.relay_info = None;
            req.options.retain(|(c, _)| *c != 82);
        }
        // RELEASE and DECLINE end a lease: on the server's own link, only
        // from the client's own Ethernet address and port (RFC 2131 has no
        // authentication, but a neighbour need not end someone else's).
        if matches!(req.kind, Kind::Release | Kind::Decline)
            && req.giaddr.is_unspecified()
            && srv.relay.is_none()
            && (*iface != srv.interface
                || (req.htype == 1 && req.hlen == 6 && heard.src_mac != req.mac()))
        {
            self.stats.drop(Drop::Unexpected);
            return out;
        }
        self.set_agent(&srv.name, &req);
        let unicast = !heard.dst.is_broadcast();
        if self.gate(now, iface, &srv, &req, unicast, &mut out) {
            return out;
        }
        match req.kind {
            Kind::Discover => self.discover(now, iface, &srv, req, None, &mut out),
            Kind::Request => self.request(now, iface, &srv, &req, unicast, &mut out),
            Kind::Decline => self.decline(now, &srv, &req, &mut out),
            Kind::Release => self.release_msg(now, &srv, &req, &mut out),
            Kind::Inform => self.inform(now, iface, &srv, &req, &mut out),
            _ => self.stats.drop(Drop::Unexpected),
        }
        self.forget_ended(&out);
        out
    }

    /// The option 82 a static lease is matched with: the request's, else
    /// the one the client's lease kept (renewals come without a relay).
    fn set_agent(&mut self, server: &str, req: &Request) {
        self.agent = req.relay_info.clone().or_else(|| {
            self.leases
                .of_client(&req.client_key(), server)
                .find_map(|l| l.relay_info.clone())
        });
    }

    /// Token bucket: `client_rate_limit` messages a second, bursts of
    /// twice that.
    fn allow(&mut self, srv: &ServerPlan, mac: [u8; 6], now_ms: u64) -> bool {
        let rate = u64::from(srv.client_rate_limit);
        if rate == 0 {
            return true;
        }
        let cap = rate.saturating_mul(2).max(4).saturating_mul(1000);
        if self.limiter.len() >= MAX_CLIENTS_TRACKED && !self.limiter.contains_key(&mac) {
            // Make room: forget the clients that are full again. At most
            // every SWEEP_MS: a sweep per new client was O(table) per
            // message once full (G4.3f, measured: 100 000 clients after a
            // power cut ran 8× slower per lease than 10 000).
            if now_ms >= self.limiter_swept_ms.saturating_add(SWEEP_MS) {
                self.limiter_swept_ms = now_ms;
                self.limiter.retain(|_, b| {
                    b.tokens
                        .saturating_add(now_ms.saturating_sub(b.at_ms).saturating_mul(rate))
                        < cap
                });
            }
            if self.limiter.len() >= MAX_CLIENTS_TRACKED {
                // Full of clients still counting: this one is served without
                // a bucket. The table stays bounded; refusing here turned a
                // storm of 100 000 legitimate clients into 34 000 refusals,
                // and a per-MAC limit does not slow a flood of random MACs
                // anyway (each is new).
                self.stats.untracked = self.stats.untracked.saturating_add(1);
                return true;
            }
        }
        let b = self.limiter.entry(mac).or_insert(Bucket {
            tokens: cap,
            at_ms: now_ms,
        });
        let refill = now_ms.saturating_sub(b.at_ms).saturating_mul(rate);
        b.tokens = b.tokens.saturating_add(refill).min(cap);
        b.at_ms = now_ms;
        if b.tokens >= 1000 {
            b.tokens -= 1000;
            true
        } else {
            false
        }
    }

    /// Another server's reply, where an alert watches (RouterOS
    /// `/ip dhcp-server alert`).
    fn observe(&mut self, now: Now, iface: &IfName, heard: &Heard, out: &mut Vec<Effect>) {
        let Some(alert) = self.plan.alert_on(iface).cloned() else {
            return;
        };
        let Some((kind, server_id)) = request::server_reply(&heard.payload) else {
            return;
        };
        if !matches!(kind, Kind::Offer | Kind::Ack | Kind::Nak)
            || alert.valid.contains(&heard.src_mac)
            || self.plan.router.contains(&heard.src)
            || server_id.is_some_and(|s| self.plan.router.contains(&s))
        {
            return;
        }
        self.stats.rogue_replies = self.stats.rogue_replies.saturating_add(1);
        let key = (iface.clone(), heard.src_mac);
        let e = self.seen.entry(key).or_insert(Seen {
            interface: iface.clone(),
            mac: heard.src_mac,
            ip: heard.src,
            server_id,
            first: now.unix,
            last: now.unix,
            count: 0,
            alerted: 0,
        });
        e.last = now.unix;
        e.ip = heard.src;
        e.server_id = server_id;
        e.count = e.count.saturating_add(1);
        if e.alerted == 0 || e.alerted.saturating_add(alert.timeout) <= now.unix {
            e.alerted = now.unix;
            out.push(Effect::Log {
                level: Level::Critical,
                text: format!(
                    "dhcp alert on {iface}: unknown DHCP server {} ({}) sent a {}",
                    server_id.unwrap_or(heard.src),
                    mac_text(&heard.src_mac),
                    kind.as_str().to_uppercase()
                ),
            });
        }
    }

    // ---- address choice ----------------------------------------------------

    /// Whether `ip` may be handed out at all by a server whose chain is
    /// `chain` (pool) — router, gateways, network and broadcast never are.
    fn usable(&self, chain: Option<&str>, ip: Ipv4Addr) -> bool {
        if self.plan.router.contains(&ip) {
            return false;
        }
        if let Some(n) = self.plan.network_of(ip) {
            if n.cfg.gateway.contains(&ip) {
                return false;
            }
            if n.net.prefix_len() < 31 && (ip == n.net.network() || ip == n.net.broadcast()) {
                return false;
            }
        }
        chain.is_some_and(|c| self.plan.pool_of(c, ip).is_some())
    }

    /// Whether `ip` may go to the client `key` on `srv` now.
    fn free_for(
        &self,
        srv: &ServerPlan,
        chain: Option<&str>,
        ip: Ipv4Addr,
        key: &[u8],
        mac: [u8; 6],
    ) -> bool {
        if let Some(s) = self.plan.static_of(&srv.name, ip) {
            return s.matches(&srv.name, key, mac, self.agent.as_deref());
        }
        if !self.usable(chain, ip) {
            return false;
        }
        match self.leases.get(ip) {
            None => true,
            Some(l) if l.client_key() == key && l.server == srv.name => {
                !matches!(l.state, State::Conflict | State::Declined)
            }
            Some(l) => l.state.free(),
        }
    }

    /// The chain a client draws from: a matcher's pool, else the server's.
    fn chain_for(&self, srv: &ServerPlan, req: &Request) -> (Option<String>, Vec<OptPlan>) {
        // A grant's pool (RADIUS `Framed-Pool`) wins, when the router has it.
        if let Some(pool) = self
            .gate
            .grant(&srv.name, &req.client_key())
            .and_then(|g| g.pool.clone())
            .filter(|p| !self.plan.chain(p).is_empty())
        {
            return (Some(pool), Vec::new());
        }
        for m in &self.plan.matchers {
            if m.hits(&srv.name, req.option(m.code)) {
                return (
                    m.pool.clone().or_else(|| srv.pool.clone()),
                    m.options.clone(),
                );
            }
        }
        (srv.pool.clone(), Vec::new())
    }

    /// The next never-used address of `chain`, else the free one idle the
    /// longest (RFC 2131 §4.3.1).
    fn pick(
        &mut self,
        srv: &ServerPlan,
        chain: &str,
        skip: &[Ipv4Addr],
        key: &[u8],
        mac: [u8; 6],
    ) -> Option<Ipv4Addr> {
        let pools: Vec<(String, Vec<corerouter_model::ip_pool::PoolRange>)> =
            self.plan.chain(chain).to_vec();
        for (name, ranges) in &pools {
            if self.exhausted.get(name) == Some(&self.generation) {
                continue;
            }
            let size: u64 = ranges.iter().map(|r| r.len()).sum();
            let start = self.cursor.get(name).copied().unwrap_or(0) % size.max(1);
            let mut found = None;
            for i in 0..size {
                let off = (start + i) % size;
                let Some(ip) = nth(ranges, off) else { continue };
                if self.leases.get(ip).is_none()
                    && !skip.contains(&ip)
                    && self.plan.static_of(&srv.name, ip).is_none()
                    && self.usable(Some(chain), ip)
                {
                    found = Some((ip, off));
                    break;
                }
            }
            match found {
                Some((ip, off)) => {
                    self.cursor.insert(name.clone(), off + 1);
                    return Some(ip);
                }
                None => {
                    // Even with `skip`: what it holds was probed and now
                    // has a record (a conflict), so it is not never-used
                    // either. Without this an attacker answering every ARP
                    // probe made each answer rescan the whole pool.
                    self.exhausted.insert(name.clone(), self.generation);
                }
            }
        }
        // Reuse: the free record idle the longest (kept in that order).
        self.leases
            .free_oldest_first()
            .filter(|l| !skip.contains(&l.address))
            .find(|l| self.free_for(srv, Some(chain), l.address, key, mac))
            .map(|l| l.address)
    }

    /// RFC 2131 §4.3.1. `(address, probe it?)`.
    fn choose(
        &mut self,
        srv: &ServerPlan,
        req: &Request,
        chain: Option<&str>,
        skip: &[Ipv4Addr],
        now: Now,
    ) -> Option<(Ipv4Addr, bool)> {
        let key = req.client_key();
        let mac = req.mac();
        // A granted address (`Framed-IP-Address`) and no other.
        if let Some(ip) = self.gate.grant(&srv.name, &key).and_then(|g| g.address) {
            return self.granted_ok(srv, ip, &key).then_some((ip, false));
        }
        if let Some(s) = self
            .plan
            .static_for(&srv.name, &key, mac, self.agent.as_deref())
        {
            return Some((s.cfg.address, false));
        }
        let mine: Vec<Lease> = self.leases.of_client(&key, &srv.name).cloned().collect();
        if let Some(l) = mine.iter().find(|l| {
            l.state.active()
                && !skip.contains(&l.address)
                && self.free_for(srv, chain, l.address, &key, mac)
        }) {
            return Some((l.address, false));
        }
        if let Some(l) = mine
            .iter()
            .filter(|l| l.state.free() && !skip.contains(&l.address))
            .filter(|l| self.free_for(srv, chain, l.address, &key, mac))
            .max_by_key(|l| l.expires)
        {
            // Probe it again after a minute away (Kea's ping-cltt-secs).
            let fresh = now.unix.saturating_sub(l.last_seen) < 60;
            return Some((l.address, !fresh));
        }
        let chain = chain?;
        if let Some(ip) = req.requested
            && !skip.contains(&ip)
            && self.free_for(srv, Some(chain), ip, &key, mac)
        {
            return Some((ip, true));
        }
        self.pick(srv, chain, skip, &key, mac).map(|ip| (ip, true))
    }

    // ---- the messages --------------------------------------------------

    fn discover(
        &mut self,
        now: Now,
        iface: &IfName,
        srv: &ServerPlan,
        req: Request,
        tried: Option<Vec<Ipv4Addr>>,
        out: &mut Vec<Effect>,
    ) {
        let key = req.client_key();
        let mac = req.mac();
        if tried.is_none() && self.parked_keys.contains(&(srv.name.clone(), key.clone())) {
            self.stats.drop(Drop::Probing);
            return;
        }
        let (chain, _) = self.chain_for(srv, &req);
        let is_static = self
            .plan
            .static_for(&srv.name, &key, mac, self.agent.as_deref())
            .is_some()
            || self
                .gate
                .grant(&srv.name, &key)
                .is_some_and(|g| g.address.is_some());
        if chain.is_none() && !is_static {
            self.stats.drop(Drop::StaticOnly);
            return;
        }
        if let Some(limit) = srv.client_mac_limit
            && !is_static
            // Not Ethernet: no MAC to count by.
            && mac != [0; 6]
        {
            let others = self
                .leases
                .of_mac(mac)
                .filter(|l| l.server == srv.name && l.state.active() && l.client_key() != key)
                .count();
            let has = self
                .leases
                .of_client(&key, &srv.name)
                .any(|l| l.state.active());
            if !has && others >= usize::try_from(limit).unwrap_or(usize::MAX) {
                self.stats.drop(Drop::MacLimit);
                return;
            }
        }
        let tried = tried.unwrap_or_default();
        let Some((ip, probe)) = self.choose(srv, &req, chain.as_deref(), &tried, now) else {
            self.stats.drop(Drop::PoolExhausted);
            let pool = chain.as_deref().unwrap_or("static-only").to_owned();
            let at = self
                .full_logged
                .entry((srv.name.clone(), pool.clone()))
                .or_insert(0);
            if *at == 0 || now.unix >= at.saturating_add(FULL_LOG_SECS) {
                *at = now.unix;
                out.push(Effect::Log {
                    level: Level::Warning,
                    text: format!(
                        "{}: no free address for {} (pool {pool} is full; more are counted as pool-exhausted)",
                        srv.name,
                        mac_text(&mac),
                    ),
                });
            }
            return;
        };
        let recently_ok = self
            .probed_ok
            .get(&ip)
            .is_some_and(|at| now.ms.saturating_sub(*at) < PROBED_OK_MS);
        let probe = probe
            && srv.conflict_detection
            && req.giaddr.is_unspecified()
            && !recently_ok
            && tried.len() < PROBE_TRIES
            && self.parked.len() < MAX_PARKED;
        if probe && let Some(src) = srv.source_for(ip) {
            self.stats.probes = self.stats.probes.saturating_add(1);
            out.push(Effect::Probe {
                interface: iface.clone(),
                ip,
                src,
            });
            let mut tried = tried;
            tried.push(ip);
            self.parked_keys.insert((srv.name.clone(), key));
            self.parked.push(Parked {
                interface: iface.clone(),
                server: srv.name.clone(),
                req,
                ip,
                deadline_ms: now.ms + PROBE_WAIT_MS,
                tried,
                matcher_pool: chain,
            });
            return;
        }
        self.offer(now, iface, srv, &req, ip, out);
    }

    /// The lease time: a grant's (`Session-Timeout`), a static lease's,
    /// else the server's.
    fn lease_time(&self, srv: &ServerPlan, st: Option<&StaticPlan>, key: &[u8]) -> u32 {
        self.gate
            .grant(&srv.name, key)
            .and_then(|g| g.lease_time)
            .filter(|t| *t > 0)
            .or_else(|| st.and_then(|s| s.cfg.lease_time))
            .unwrap_or(srv.lease_time)
    }

    /// Whether a granted address may go to `key`: on this server's
    /// network, not the router's, and nobody else's now.
    fn granted_ok(&self, srv: &ServerPlan, ip: Ipv4Addr, key: &[u8]) -> bool {
        if self.plan.router.contains(&ip) || !self.on_network(srv, ip) {
            return false;
        }
        match self.leases.get(ip) {
            None => true,
            Some(l) if l.client_key() == key && l.server == srv.name => {
                !matches!(l.state, State::Conflict | State::Declined)
            }
            Some(l) => l.state.free(),
        }
    }

    fn host_of(req: &Request) -> String {
        // RFC 4702 §4: option 81 wins over 12.
        match (&req.fqdn, &req.host_name) {
            (Some(f), _) if !f.name.is_empty() => f.name.clone(),
            (_, Some(h)) => h.clone(),
            _ => String::new(),
        }
    }

    /// A record of `req`'s client at `ip`, `state` until `until` (the
    /// granted lease time and that end).
    fn record_for(
        &self,
        srv: &ServerPlan,
        req: &Request,
        ip: Ipv4Addr,
        state: State,
        until: (u64, u32),
        now: Now,
    ) -> Lease {
        let (expires, lease_time) = until;
        Lease {
            address: ip,
            server: srv.name.clone(),
            state,
            mac: req.mac(),
            client_id: req.client_id.clone(),
            host_name: Self::host_of(req),
            vendor_class: req
                .vendor_class
                .as_deref()
                .map(|v| crate::v4::clip(&String::from_utf8_lossy(v)))
                .unwrap_or_default(),
            expires,
            lease_time,
            last_seen: now.unix,
            reason: String::new(),
            // The request's option 82, else the one the client's lease kept
            // (a renewal comes straight, without it): `set_agent`.
            relay_info: self.agent.clone(),
            hw: (!(req.htype == 1 && req.hlen == 6) && req.client_id.is_none())
                .then(|| req.client_key()),
        }
    }

    fn offer(
        &mut self,
        now: Now,
        iface: &IfName,
        srv: &ServerPlan,
        req: &Request,
        ip: Ipv4Addr,
        out: &mut Vec<Effect>,
    ) {
        let key = req.client_key();
        let st = self
            .plan
            .static_for(&srv.name, &key, req.mac(), self.agent.as_deref())
            .cloned();
        let lt = self.lease_time(srv, st.as_ref(), &key);
        match self.leases.get(ip) {
            Some(l) if l.state == State::Bound && l.client_key() == key && l.server == srv.name => {
            }
            _ => {
                let rec = self.record_for(
                    srv,
                    req,
                    ip,
                    State::Offered,
                    (now.unix + OFFER_HOLD, lt),
                    now,
                );
                self.leases.put(rec);
            }
        }
        self.reply(
            now,
            iface,
            srv,
            req,
            Kind::Offer,
            ip,
            Some(lt),
            st.as_ref(),
            out,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn reply(
        &mut self,
        now: Now,
        iface: &IfName,
        srv: &ServerPlan,
        req: &Request,
        kind: Kind,
        ip: Ipv4Addr,
        lease: Option<u32>,
        st: Option<&StaticPlan>,
        out: &mut Vec<Effect>,
    ) {
        let at = if ip.is_unspecified() { req.ciaddr } else { ip };
        let Some(src) = srv.source_for(at) else {
            self.stats.drop(Drop::NoServer);
            return;
        };
        let net = self.plan.network_of(at).cloned();
        let blocked = st.is_some_and(|s| s.cfg.block_access);
        let asked = |code: u8| req.params.is_empty() || req.params.contains(&code);
        let mut opts: Vec<(u8, Vec<u8>)> = Vec::new();
        opts.push((54, src.octets().to_vec()));
        if let Some(lt) = lease {
            opts.push((51, lt.to_be_bytes().to_vec()));
            // RFC 2131 §4.4.5.
            opts.push((58, (lt / 2).to_be_bytes().to_vec()));
            opts.push((59, (lt / 8 * 7).to_be_bytes().to_vec()));
        }
        let prefix = net
            .as_ref()
            .map(|n| n.cfg.netmask.unwrap_or(n.net.prefix_len()))
            .or_else(|| {
                srv.on_link
                    .iter()
                    .find(|n| n.contains(&at))
                    .map(|n| n.prefix_len())
            });
        if let Some(p) = prefix {
            let mask = u32::MAX.checked_shl(32 - u32::from(p.min(32))).unwrap_or(0);
            opts.push((1, mask.to_be_bytes().to_vec()));
        }
        let mut extra: Vec<OptPlan> = srv.options.clone();
        if let Some(n) = &net {
            let ips = |v: &[Ipv4Addr]| v.iter().flat_map(|a| a.octets()).collect::<Vec<u8>>();
            if !blocked && !n.cfg.gateway.is_empty() && asked(3) {
                opts.push((3, ips(&n.cfg.gateway)));
            }
            if !blocked && !n.dns.is_empty() && asked(6) {
                opts.push((6, ips(&n.dns)));
            }
            if !n.cfg.domain.is_empty() && asked(15) {
                opts.push((15, n.cfg.domain.as_bytes().to_vec()));
            }
            if !n.cfg.ntp_server.is_empty() && asked(42) {
                opts.push((42, ips(&n.cfg.ntp_server)));
            }
            if !n.cfg.wins_server.is_empty() && asked(44) {
                opts.push((44, ips(&n.cfg.wins_server)));
            }
            extra.extend(n.options.iter().cloned());
        }
        if kind != Kind::Nak {
            let (_, matched) = self.chain_for(srv, req);
            extra.extend(matched);
            if let Some(s) = st {
                extra.extend(s.options.iter().cloned());
            }
        }
        // Later ones (lease > matcher > network > server) win.
        let mut chosen: BTreeMap<u8, (Vec<u8>, bool)> = BTreeMap::new();
        let host = Self::host_of(req);
        for o in &extra {
            if let Some(b) = o.bytes(&host, req.mac()) {
                chosen.insert(o.code, (b, o.force));
            }
        }
        // RFC 6842 §3, RFC 3046 §2.2.
        if let Some(id) = &req.client_id {
            opts.push((61, id.clone()));
        }
        if kind != Kind::Nak
            && let Some(f) = &req.fqdn
        {
            opts.push((
                81,
                self.fqdn_reply(f, net.as_ref().and_then(|n| n.cfg.dns_zone.as_deref())),
            ));
        }
        if let Some(r) = &req.relay_info {
            opts.push((82, r.clone()));
        }
        let head = reply::Head {
            kind,
            ciaddr: if kind == Kind::Ack {
                req.ciaddr
            } else {
                Ipv4Addr::UNSPECIFIED
            },
            yiaddr: ip,
            siaddr: if kind == Kind::Nak {
                Ipv4Addr::UNSPECIFIED
            } else {
                net.as_ref().and_then(|n| n.cfg.next_server).unwrap_or(src)
            },
            file: net
                .as_ref()
                .map(|n| n.cfg.boot_file_name.clone())
                .filter(|f| kind != Kind::Nak && !f.is_empty()),
        };
        let limit = usize::from(req.max_size.unwrap_or(576)).saturating_sub(28);
        let build = |with_unforced: bool| {
            let mut all = opts.clone();
            if kind != Kind::Nak {
                for (code, (b, force)) in &chosen {
                    if all.iter().any(|(c, _)| c == code) {
                        continue;
                    }
                    if *force || (with_unforced && req.params.contains(code)) {
                        all.push((*code, b.clone()));
                    }
                }
            }
            reply::encode(req, &head, &all)
        };
        let payload = match build(true) {
            Some(p) if p.len() <= limit.max(548) => Some(p),
            _ => build(false),
        };
        let Some(payload) = payload else {
            self.stats.drop(Drop::Malformed);
            return;
        };
        let to = if !req.giaddr.is_unspecified() {
            ReplyTo::Relay(req.giaddr)
        } else if kind == Kind::Nak {
            ReplyTo::Broadcast
        } else if !req.ciaddr.is_unspecified() {
            ReplyTo::Unicast(req.ciaddr)
        } else if req.broadcast
            || srv.always_broadcast
            || st.is_some_and(|s| s.cfg.always_broadcast)
            || !(req.htype == 1 && req.hlen == 6)
        {
            ReplyTo::Broadcast
        } else {
            ReplyTo::Client { ip, mac: req.mac() }
        };
        self.stats.sent(kind, now.unix);
        out.push(Effect::Send {
            interface: iface.clone(),
            payload,
            src,
            to,
            kind,
        });
    }

    /// RFC 4702 §4: the server's option 81.
    fn fqdn_reply(&self, f: &request::Fqdn, zone: Option<&str>) -> Vec<u8> {
        let mut flags = f.flags & FQDN_E;
        if f.flags & FQDN_N != 0 || zone.is_none() {
            // The client asked for no update, or we do none here.
            flags |= FQDN_N;
        } else {
            flags |= FQDN_S;
            if f.flags & FQDN_S == 0 {
                flags |= FQDN_O;
            }
        }
        let mut out = vec![flags, 255, 255];
        if flags & FQDN_E != 0 {
            for label in f.name.split('.').filter(|l| !l.is_empty()) {
                let l = label.as_bytes();
                let n = l.len().min(63);
                out.push(u8::try_from(n).unwrap_or(63));
                out.extend_from_slice(l.get(..n).unwrap_or(&[]));
            }
            out.push(0);
        } else {
            out.extend_from_slice(f.name.as_bytes());
        }
        out
    }

    fn nak(
        &mut self,
        now: Now,
        iface: &IfName,
        srv: &ServerPlan,
        req: &Request,
        why: &str,
        out: &mut Vec<Effect>,
    ) {
        let at = req.requested.unwrap_or(req.ciaddr);
        let Some(src) = srv.source_for(at) else {
            self.stats.drop(Drop::NoServer);
            return;
        };
        let mut opts: Vec<(u8, Vec<u8>)> =
            vec![(54, src.octets().to_vec()), (56, why.as_bytes().to_vec())];
        if let Some(id) = &req.client_id {
            opts.push((61, id.clone()));
        }
        if let Some(r) = &req.relay_info {
            opts.push((82, r.clone()));
        }
        let head = reply::Head {
            kind: Kind::Nak,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            file: None,
        };
        let Some(payload) = reply::encode(req, &head, &opts) else {
            self.stats.drop(Drop::Malformed);
            return;
        };
        let to = if req.giaddr.is_unspecified() {
            ReplyTo::Broadcast
        } else {
            ReplyTo::Relay(req.giaddr)
        };
        self.stats.sent(Kind::Nak, now.unix);
        out.push(Effect::Send {
            interface: iface.clone(),
            payload,
            src,
            to,
            kind: Kind::Nak,
        });
        out.push(Effect::Log {
            level: Level::Info,
            text: format!(
                "{}: NAK to {} for {at}: {why}",
                srv.name,
                mac_text(&req.mac())
            ),
        });
    }

    /// Whether the address is on this server's link (RFC 2131 §4.3.2
    /// "wrong network").
    fn on_network(&self, srv: &ServerPlan, ip: Ipv4Addr) -> bool {
        if srv.relay.is_some() {
            return self.plan.network_of(ip).is_some();
        }
        srv.on_link.iter().any(|n| n.contains(&ip))
    }

    fn request(
        &mut self,
        now: Now,
        iface: &IfName,
        srv: &ServerPlan,
        req: &Request,
        unicast: bool,
        out: &mut Vec<Effect>,
    ) {
        let key = req.client_key();
        let mac = req.mac();
        let (chain, _) = self.chain_for(srv, req);
        let chain = chain.as_deref();
        // SELECTING: option 54 present.
        if let Some(sid) = req.server_id {
            if !srv.is_me(sid) {
                // §3.1 step 3: the client took another server's offer.
                let offered: Vec<Ipv4Addr> = self
                    .leases
                    .of_client(&key, &srv.name)
                    .filter(|l| l.state == State::Offered)
                    .map(|l| l.address)
                    .collect();
                for ip in offered {
                    self.leases.get_mut_with(ip, |l| {
                        l.state = State::Expired;
                        l.expires = now.unix;
                    });
                }
                self.stats.drop(Drop::OtherServer);
                return;
            }
            let ip = req.requested.unwrap_or(req.ciaddr);
            let ours = self
                .leases
                .get(ip)
                .is_some_and(|l| l.client_key() == key && l.server == srv.name && l.state.active());
            let is_static = self
                .plan
                .static_for(&srv.name, &key, mac, self.agent.as_deref())
                .is_some_and(|s| s.cfg.address == ip)
                || self
                    .gate
                    .grant(&srv.name, &key)
                    .and_then(|g| g.address)
                    .is_some_and(|g| g == ip && self.granted_ok(srv, ip, &key));
            if ours || is_static {
                self.ack(now, iface, srv, req, ip, out);
            } else {
                // §3.1 step 4: we cannot give what we offered any more.
                self.nak(now, iface, srv, req, "address not offered to you", out);
            }
            return;
        }
        let renewing = !req.ciaddr.is_unspecified();
        let Some(ip) = (if renewing {
            Some(req.ciaddr)
        } else {
            req.requested
        }) else {
            self.stats.drop(Drop::Malformed);
            return;
        };
        let may_nak = srv.authoritative.naks_after(req.secs) || (renewing && unicast);
        if !renewing && !self.on_network(srv, ip) {
            // INIT-REBOOT on the wrong network: SHOULD NAK.
            if may_nak {
                self.nak(now, iface, srv, req, "wrong network", out);
            } else {
                self.stats.drop(Drop::NotAuthoritative);
            }
            return;
        }
        let record = self.leases.get(ip).cloned();
        let known = record
            .as_ref()
            .is_some_and(|l| l.client_key() == key && l.server == srv.name);
        let granted = self.gate.grant(&srv.name, &key).and_then(|g| g.address);
        let ok = match granted {
            // A granted address is the only one this client may have.
            Some(g) => g == ip && self.granted_ok(srv, ip, &key),
            None => {
                self.free_for(srv, chain, ip, &key, mac)
                    || self
                        .plan
                        .static_for(&srv.name, &key, mac, self.agent.as_deref())
                        .is_some_and(|s| s.cfg.address == ip)
            }
        };
        if ok && (known || may_nak) {
            // Ours, or (authoritative) free and valid for this client: the
            // table is rebuilt from what clients hold.
            self.ack(now, iface, srv, req, ip, out);
            return;
        }
        let knows_client = self.leases.of_client(&key, &srv.name).next().is_some();
        if !ok && (may_nak || knows_client) {
            self.nak(now, iface, srv, req, "address not available", out);
        } else {
            // §4.3.2 INIT-REBOOT: no record of the client: MUST be silent.
            self.stats.drop(Drop::NotAuthoritative);
        }
    }

    fn ack(
        &mut self,
        now: Now,
        iface: &IfName,
        srv: &ServerPlan,
        req: &Request,
        ip: Ipv4Addr,
        out: &mut Vec<Effect>,
    ) {
        let key = req.client_key();
        let st = self
            .plan
            .static_for(&srv.name, &key, req.mac(), self.agent.as_deref())
            .cloned();
        let lt = self.lease_time(srv, st.as_ref(), &key);
        // The client's other addresses on this server end (it moved).
        let old: Vec<Ipv4Addr> = self
            .leases
            .of_client(&key, &srv.name)
            .filter(|l| l.address != ip && l.state.active())
            .map(|l| l.address)
            .collect();
        for a in old {
            if let Some(l) = self.leases.get_mut_with(a, |l| {
                l.state = State::Released;
                l.expires = now.unix;
            }) {
                out.push(Effect::Journal(Record::Lease(l.clone())));
                out.push(Effect::Gone(l));
            }
        }
        let prev = self.leases.get(ip).cloned();
        let mut rec = self.record_for(
            srv,
            req,
            ip,
            State::Bound,
            (now.unix + u64::from(lt), lt),
            now,
        );
        if rec.host_name.is_empty()
            && let Some(p) = prev.as_ref().filter(|p| p.client_key() == key)
        {
            rec.host_name = p.host_name.clone();
        }
        let renewed = prev
            .as_ref()
            .is_some_and(|p| p.state == State::Bound && p.client_key() == key);
        if let Some(p) = prev
            .as_ref()
            .filter(|p| p.state == State::Bound && p.client_key() != key)
        {
            // An authoritative take-over of a stale binding.
            out.push(Effect::Gone(p.clone()));
        }
        self.leases.put(rec.clone());
        out.push(Effect::Journal(Record::Lease(rec.clone())));
        let no_update = req.fqdn.as_ref().is_some_and(|f| f.flags & FQDN_N != 0);
        let (dns, lists) = self.outside(srv, st.as_ref(), ip, &rec.host_name, no_update, &key);
        if !renewed {
            out.push(Effect::Log {
                level: Level::Info,
                text: format!(
                    "{} assigned {ip} to {}{}",
                    srv.name,
                    mac_text(&rec.mac),
                    if rec.host_name.is_empty() {
                        String::new()
                    } else {
                        format!(" ({})", rec.host_name)
                    }
                ),
            });
        }
        out.push(Effect::Bound(Binding {
            new: !renewed,
            lease: rec,
            dns,
            ttl: dns_ttl(lt),
            address_lists: lists,
        }));
        self.reply(
            now,
            iface,
            srv,
            req,
            Kind::Ack,
            ip,
            Some(lt),
            st.as_ref(),
            out,
        );
    }

    /// What a binding of `ip` means outside the server: its DNS name
    /// (zone, label) and its address lists. The static lease's name wins
    /// over the client's.
    fn outside(
        &self,
        srv: &ServerPlan,
        st: Option<&StaticPlan>,
        ip: Ipv4Addr,
        host_name: &str,
        no_update: bool,
        key: &[u8],
    ) -> (Option<(String, String)>, Vec<String>) {
        let label = st
            .map(|s| s.cfg.host_name.clone())
            .filter(|h| !h.is_empty())
            .unwrap_or_else(|| dns_label(host_name));
        let dns = self
            .plan
            .network_of(ip)
            .and_then(|n| n.cfg.dns_zone.clone())
            .filter(|_| !label.is_empty() && !no_update)
            .map(|z| (z, dns_label(&label)));
        let mut lists = srv.address_lists.clone();
        if let Some(s) = st {
            lists.extend(s.cfg.address_lists.iter().map(|n| n.as_str().to_owned()));
        }
        if let Some(g) = self.gate.grant(&srv.name, key) {
            for l in &g.address_lists {
                if !lists.contains(l) {
                    lists.push(l.clone());
                }
            }
        }
        (dns, lists)
    }

    /// The binding a bound record stands for (after a restart: its DNS
    /// name and address lists are put back from it). `None` when the
    /// record is not bound or its server is gone.
    pub fn binding_of(&self, l: &Lease) -> Option<Binding> {
        if l.state != State::Bound {
            return None;
        }
        let srv = self.server(&l.server)?;
        let st = self
            .plan
            .static_for(&srv.name, &l.client_key(), l.mac, l.relay_info.as_deref())
            .filter(|s| s.cfg.address == l.address);
        let (dns, address_lists) =
            self.outside(srv, st, l.address, &l.host_name, false, &l.client_key());
        Some(Binding {
            lease: l.clone(),
            new: false,
            dns,
            ttl: dns_ttl(l.lease_time),
            address_lists,
        })
    }

    fn decline(&mut self, now: Now, srv: &ServerPlan, req: &Request, out: &mut Vec<Effect>) {
        let key = req.client_key();
        let Some(ip) = req.requested else {
            self.stats.drop(Drop::Malformed);
            return;
        };
        let mine = self
            .leases
            .get(ip)
            .is_some_and(|l| l.client_key() == key && l.server == srv.name && l.state.active());
        if !mine {
            self.stats.drop(Drop::Unexpected);
            return;
        }
        let hold = u64::from(srv.lease_time);
        if let Some(l) = self.leases.get_mut_with(ip, |l| {
            l.state = State::Declined;
            l.expires = now.unix + hold;
            l.reason = format!("declined by {} (address in use)", mac_text(&l.mac));
        }) {
            self.stats.conflicts = self.stats.conflicts.saturating_add(1);
            out.push(Effect::Journal(Record::Lease(l.clone())));
            out.push(Effect::Log {
                level: Level::Warning,
                text: format!("{}: {ip} {}", srv.name, l.reason),
            });
            out.push(Effect::Gone(l));
        }
    }

    fn release_msg(&mut self, now: Now, srv: &ServerPlan, req: &Request, out: &mut Vec<Effect>) {
        let key = req.client_key();
        let ip = req.ciaddr;
        let mine = self.leases.get(ip).is_some_and(|l| {
            l.client_key() == key && l.server == srv.name && l.state == State::Bound
        });
        if !mine {
            self.stats.drop(Drop::Unexpected);
            return;
        }
        self.end(ip, State::Released, now, "released by the client", out);
    }

    fn end(&mut self, ip: Ipv4Addr, state: State, now: Now, why: &str, out: &mut Vec<Effect>) {
        if let Some(l) = self.leases.get_mut_with(ip, |l| {
            l.state = state;
            l.expires = now.unix;
        }) {
            out.push(Effect::Journal(Record::Lease(l.clone())));
            out.push(Effect::Log {
                level: Level::Info,
                text: format!("{} {ip} of {}: {why}", l.server, mac_text(&l.mac)),
            });
            out.push(Effect::Gone(l));
        }
    }

    fn inform(
        &mut self,
        now: Now,
        iface: &IfName,
        srv: &ServerPlan,
        req: &Request,
        out: &mut Vec<Effect>,
    ) {
        if req.ciaddr.is_unspecified() {
            self.stats.drop(Drop::Malformed);
            return;
        }
        let st = self
            .plan
            .static_for(
                &srv.name,
                &req.client_key(),
                req.mac(),
                self.agent.as_deref(),
            )
            .cloned();
        // §4.3.5: no lease time, no yiaddr.
        self.reply(
            now,
            iface,
            srv,
            req,
            Kind::Ack,
            Ipv4Addr::UNSPECIFIED,
            None,
            st.as_ref(),
            out,
        );
    }

    // ---- probes and time -----------------------------------------------

    /// A host answered for `ip` on `iface` (ARP).
    pub fn probe_reply(
        &mut self,
        now: Now,
        iface: &IfName,
        ip: Ipv4Addr,
        mac: [u8; 6],
    ) -> Vec<Effect> {
        let mut out = Vec::new();
        if self.checking.remove(&ip).is_some()
            && let Some(l) = self.leases.get_mut_with(ip, |l| {
                l.reason = format!("ARP reply from {}", mac_text(&mac));
                l.expires = now.unix + u64::from(l.lease_time.max(60));
            })
        {
            out.push(Effect::Journal(Record::Lease(l.clone())));
            out.push(Effect::Log {
                level: Level::Warning,
                text: format!("{}: {ip} is still in use: {}", l.server, l.reason),
            });
        }
        let Some(pos) = self
            .parked
            .iter()
            .position(|p| p.ip == ip && p.interface == *iface)
        else {
            return out;
        };
        let p = self.parked.remove(pos);
        self.parked_keys
            .remove(&(p.server.clone(), p.req.client_key()));
        let Some(srv) = self.server(&p.server).cloned() else {
            return out;
        };
        if p.req.htype == 1 && p.req.hlen == 6 && mac == p.req.mac() {
            // The client itself still holds the address (RFC 5227 hosts
            // answer for theirs): not a conflict, offer it now.
            self.probed_ok.insert(p.ip, now.ms);
            self.set_agent(&srv.name, &p.req);
            let key = p.req.client_key();
            if self.free_for(&srv, p.matcher_pool.as_deref(), p.ip, &key, mac) {
                self.offer(now, &p.interface, &srv, &p.req, p.ip, &mut out);
            }
            return out;
        }
        self.stats.conflicts = self.stats.conflicts.saturating_add(1);
        self.set_agent(&srv.name, &p.req);
        let mut rec = self.record_for(
            &srv,
            &p.req,
            ip,
            State::Conflict,
            (now.unix + u64::from(srv.lease_time), srv.lease_time),
            now,
        );
        // The record is the squatter's, not the client's.
        rec.mac = mac;
        rec.client_id = None;
        rec.host_name.clear();
        rec.vendor_class.clear();
        rec.relay_info = None;
        rec.reason = format!("ARP reply from {} before the offer", mac_text(&mac));
        self.leases.put(rec.clone());
        out.push(Effect::Journal(Record::Lease(rec.clone())));
        out.push(Effect::Log {
            level: Level::Warning,
            text: format!(
                "{}: {ip} conflict: {}; offering another address",
                srv.name, rec.reason
            ),
        });
        let iface = p.interface.clone();
        self.discover(now, &iface, &srv, p.req, Some(p.tried), &mut out);
        out
    }

    /// Run often (every service round): probes whose wait is over.
    pub fn tick_ms(&mut self, now: Now) -> Vec<Effect> {
        let mut out = Vec::new();
        self.gate_tick(now);
        let (due, wait): (Vec<Parked>, Vec<Parked>) = std::mem::take(&mut self.parked)
            .into_iter()
            .partition(|p| p.deadline_ms <= now.ms);
        self.parked = wait;
        for p in &due {
            self.parked_keys
                .remove(&(p.server.clone(), p.req.client_key()));
        }
        for p in due {
            let Some(srv) = self.server(&p.server).cloned() else {
                continue;
            };
            self.probed_ok.insert(p.ip, now.ms);
            self.set_agent(&srv.name, &p.req);
            // Still free? (a static lease or another client may have taken
            // it while we waited)
            let key = p.req.client_key();
            if self.free_for(&srv, p.matcher_pool.as_deref(), p.ip, &key, p.req.mac()) {
                self.offer(now, &p.interface, &srv, &p.req, p.ip, &mut out);
            }
        }
        let checked: Vec<Ipv4Addr> = self
            .checking
            .iter()
            .filter(|(_, (_, d))| *d <= now.ms)
            .map(|(ip, _)| *ip)
            .collect();
        for ip in checked {
            self.checking.remove(&ip);
            self.end(
                ip,
                State::Expired,
                now,
                "check-status: nobody answers, free again",
                &mut out,
            );
        }
        if self.probed_ok.len() > MAX_PARKED * 4 {
            self.probed_ok
                .retain(|_, at| now.ms.saturating_sub(*at) < PROBED_OK_MS);
        }
        self.forget_ended(&out);
        out
    }

    /// Run once a second: leases, offers and holds that ran out; alerts
    /// that timed out.
    pub fn tick(&mut self, now: Now) -> Vec<Effect> {
        let mut out = self.tick_ms(now);
        if now.unix == self.last_tick {
            return out;
        }
        self.last_tick = now.unix;
        let due: Vec<(Ipv4Addr, State)> = self
            .leases
            .iter()
            .filter(|l| !l.state.free() && l.expires <= now.unix)
            .map(|l| (l.address, l.state))
            .collect();
        for (ip, state) in due {
            match state {
                State::Bound => self.end(ip, State::Expired, now, "lease expired", &mut out),
                State::Offered => {
                    // Never journaled: just free.
                    self.leases.get_mut_with(ip, |l| {
                        l.state = State::Expired;
                    });
                }
                State::Conflict | State::Declined if !self.checking.contains_key(&ip) => {
                    if let Some(l) = self.leases.get_mut_with(ip, |l| {
                        l.state = State::Expired;
                        l.reason.clear();
                    }) {
                        out.push(Effect::Journal(Record::Lease(l)));
                    }
                }
                _ => {}
            }
        }
        // Free records too old to be worth remembering go.
        let old: Vec<Ipv4Addr> = self
            .leases
            .iter()
            .filter(|l| l.state.free() && l.expires.saturating_add(KEEP_FREE_SECS) <= now.unix)
            .map(|l| l.address)
            .collect();
        if !old.is_empty() {
            for ip in old {
                self.leases.remove(ip);
                out.push(Effect::Journal(Record::Forget { forget: ip }));
            }
            self.generation += 1;
        }
        let alerts = self.plan.alerts.clone();
        for a in &alerts {
            let last = self.alert_probe.get(&a.interface).copied().unwrap_or(0);
            if now.unix >= last.saturating_add(ALERT_PROBE_SECS) {
                self.alert_probe.insert(a.interface.clone(), now.unix);
                out.push(Effect::Discover {
                    interface: a.interface.clone(),
                });
            }
        }
        self.alert_probe
            .retain(|i, _| alerts.iter().any(|a| a.interface == *i));
        self.seen.retain(|(i, _), s| {
            let timeout = alerts
                .iter()
                .find(|a| a.interface == *i)
                .map_or(0, |a| a.timeout);
            s.last.saturating_add(timeout) > now.unix
        });
        self.forget_ended(&out);
        out
    }

    // ---- the operator --------------------------------------------------

    /// `ip.dhcp-server.lease.release`: a dynamic lease ends now.
    pub fn release(&mut self, ip: Ipv4Addr, now: Now) -> Result<Vec<Effect>, String> {
        let Some(l) = self.leases.get(ip) else {
            return Err(format!("no lease for {ip}"));
        };
        if !l.state.active() && !matches!(l.state, State::Conflict | State::Declined) {
            return Err(format!("{ip} is {} already", l.state.as_str()));
        }
        let mut out = Vec::new();
        self.end(
            ip,
            State::Released,
            now,
            "released by the operator",
            &mut out,
        );
        self.generation += 1;
        self.forget_ended(&out);
        Ok(out)
    }

    /// `ip.dhcp-server.lease.remove` of a dynamic lease: forgotten.
    pub fn forget(&mut self, ip: Ipv4Addr) -> Vec<Effect> {
        let mut out = Vec::new();
        if let Some(l) = self.leases.remove(ip) {
            if l.state == State::Bound {
                out.push(Effect::Gone(l));
            }
            out.push(Effect::Journal(Record::Forget { forget: ip }));
            self.generation += 1;
        }
        self.forget_ended(&out);
        out
    }

    /// G4.3hd: the bindings of server `servers`' clients as the other BNG
    /// of a redundant pair had them, at its takeover: each one in (journal
    /// included); this node's own bound leases of those servers that the
    /// pair does not know end (they are older than the pair's table).
    /// RFC 2131 §4.3.2: the renewal of an adopted client then finds its
    /// binding, as on the node that granted it.
    pub fn adopt(&mut self, servers: &[String], leases: Vec<Lease>) -> Vec<Effect> {
        let keep: std::collections::HashSet<Ipv4Addr> = leases.iter().map(|l| l.address).collect();
        let stale: Vec<Ipv4Addr> = self
            .leases
            .iter()
            .filter(|l| {
                l.state == State::Bound && servers.contains(&l.server) && !keep.contains(&l.address)
            })
            .map(|l| l.address)
            .collect();
        let mut out = Vec::new();
        for ip in stale {
            out.extend(self.forget(ip));
        }
        for mut l in leases {
            if !servers.contains(&l.server) {
                continue;
            }
            l.state = State::Bound;
            out.push(Effect::Journal(Record::Lease(l.clone())));
            self.leases.put(l);
        }
        self.generation += 1;
        out
    }

    /// `ip.dhcp-server.lease.check-status` (RouterOS): probe a conflicted
    /// or declined address again; free it if nobody answers.
    pub fn check_status(&mut self, ip: Ipv4Addr, now: Now) -> Result<Vec<Effect>, String> {
        let Some(l) = self.leases.get(ip) else {
            return Err(format!("no lease for {ip}"));
        };
        if !matches!(l.state, State::Conflict | State::Declined) {
            return Err(format!("{ip} is {}, not in conflict", l.state.as_str()));
        }
        let Some(srv) = self.server(&l.server).cloned() else {
            return Err(format!("server {} is gone", l.server));
        };
        let Some(src) = srv.source_for(ip) else {
            return Err(format!("{} has no address to probe from", srv.name));
        };
        self.checking
            .insert(ip, (srv.interface.clone(), now.ms + PROBE_WAIT_MS));
        Ok(vec![Effect::Probe {
            interface: srv.interface.clone(),
            ip,
            src,
        }])
    }

    /// Use of every pool a server draws from (bound, on offer, held by a
    /// conflict).
    pub fn pool_use(&self) -> Vec<PoolUse> {
        let mut out: Vec<PoolUse> = self
            .plan
            .pools
            .pools
            .iter()
            .map(|p| PoolUse {
                pool: p.name.clone(),
                size: p.size(),
                bound: 0,
                offered: 0,
                held: 0,
            })
            .collect();
        for l in self.leases.iter() {
            let Some(u) = self
                .plan
                .pools
                .pools
                .iter()
                .position(|p| p.contains(l.address))
                .and_then(|i| out.get_mut(i))
            else {
                continue;
            };
            match l.state {
                State::Bound => u.bound += 1,
                State::Offered => u.offered += 1,
                State::Conflict | State::Declined => u.held += 1,
                _ => {}
            }
        }
        out
    }
}

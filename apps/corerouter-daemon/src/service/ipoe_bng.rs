//! The IPoE subscribers (G4.3f) of the `ipoe` service, without I/O: a
//! DHCPv4 lease of a server with `ipoe=yes` or `use_radius` is a session.
//! The engine's DHCP server calls [`Backend`] (`IpoeBackend`) under the
//! session lock: authorize a client (the local `/ppp secret`, else RADIUS
//! `service=dhcp`), a lease bound or gone. The service's thread
//! (`ipoe.rs`) takes what this core asks — the XDP map changes, the ARP
//! pings — and feeds it the XDP counters. `ppp.active`, `ppp.why` and
//! `ppp.history` read it through [`Sessions`] (`PppBackend`), RADIUS
//! CoA/Disconnect through [`Owner`].
//!
//! Locks: one mutex, [`Core::st`], held only for memory work. The AAA
//! service is called after it is let go (its callback may run at once and
//! takes it again), and the session lock is never taken here.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use corerouter_engine::framed::{self, Forbidden, FramedTable, Holder};
use corerouter_engine::ipoe::{IpoeBackend, IpoeView, Local, Revoke, local_verdict, user_of};
use corerouter_engine::ppp::PppBackend;
use corerouter_engine::radius::{AaaBackend, AcctSource, SessionOwner};
use corerouter_hal::pppoe::{PppoeCounters, PppoeSession, Rate};
use corerouter_model::dhcp_server::DhcpServer;
use corerouter_model::framed_route::{FramedRoute, RouteOrigin};
use corerouter_model::ipoe::UseRadius;
use corerouter_model::ppp::{
    ActiveSession, DEFAULT_PROFILE, HistoryEntry, ServiceStats, Stage, Why,
};
use corerouter_model::radius::{
    AaaService, AcctCounters, AcctRequest, AcctStatus, Attribute, AuthOutcome, AuthReply,
    AuthRequest, CoaKind, CoaOutcome, CoaRequest, Credentials,
};
use corerouter_model::{Config, IfName, MacAddr};
use corerouter_proto_dhcp::server::Binding;
use corerouter_proto_dhcp::server::agent;
use corerouter_proto_dhcp::server::authorize::{AuthAsk, Grant, Verdict};
use corerouter_proto_dhcp::server::leases::Lease;
use corerouter_proto_radius::rate_limit::RateLimit;
use ipnet::{IpNet, Ipv4Net};

/// Lines `ppp.history` keeps of IPoE (as the PPPoE service).
pub(crate) const HISTORY: usize = 50_000;
/// Users and MACs `ppp.why` remembers.
const WHY_KEYS: usize = 100_000;
/// XDP slots: from the top of the shared session map down, at most half
/// of it; the PPPoE service takes the lower half (`pppoe_bng::XDP_SLOTS`).
pub(crate) const SLOT_TOP: u32 = (1 << 17) - 1;
pub(crate) const SLOTS: u32 = 1 << 16;
/// RADIUS asks waiting at once (the DHCP server parks 8192).
const MAX_ASKED: usize = 8192;
/// A RADIUS answer this late is dropped (the DHCP server gave up at 15 s).
const ASK_GRACE_MS: u64 = 16_000;
/// Keepalive: pings this far apart, and this many unanswered end it.
pub(crate) const PING_EVERY_MS: u64 = 10_000;
pub(crate) const PING_TRIES: u32 = 3;
/// RFC 2865 §5.41 NAS-Port-Type Ethernet.
const NAS_PORT_ETHERNET: &str = "15";

/// IPv6 routes cannot reach an IPoE subscriber yet (IPoE is IPv4, G4.3s).
const NO_V6: &str = "o IPoE ainda não tem IPv6 (G4.3s)";

/// RFC 2866 §5.10 Acct-Terminate-Cause.
// The bench includes this file by path: its submodule says where it is.
#[path = "ipoe_bng/ha.rs"]
pub(crate) mod ha;

mod cause {
    pub const USER_REQUEST: u32 = 1;
    pub const LOST_CARRIER: u32 = 2;
    pub const LOST_SERVICE: u32 = 3;
    pub const ADMIN_RESET: u32 = 6;
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

type Key = (String, Vec<u8>);

/// What an authorization left for the session (RADIUS reply, secret).
#[derive(Debug, Clone, Default)]
struct Authz {
    user: String,
    radius: bool,
    rate: Option<String>,
    interim: Option<u32>,
    /// RFC 2865 §5.25: the Accept's Class attributes, byte for byte.
    class: Vec<Vec<u8>>,
    profile: String,
    /// G4.3cd: the routes of the Accept and the texts refused already.
    routes: Vec<(FramedRoute, RouteOrigin)>,
    refused: Vec<String>,
}

/// A RADIUS ask in flight.
struct Asked {
    at_ms: u64,
    user: String,
    mac: String,
}

/// One session (a bound lease).
#[derive(Debug, Clone)]
struct Sub {
    id: String,
    key: Key,
    user: String,
    ip: Ipv4Addr,
    mac: [u8; 6],
    server: String,
    interface: IfName,
    slot: Option<u32>,
    rate: Option<String>,
    acct: bool,
    acct_id: String,
    interim: Option<u32>,
    /// RFC 2865 §5.25: the Accept's Class attributes, byte for byte.
    class: Vec<Vec<u8>>,
    up_at: u64,
    keepalive: Option<u32>,
    /// Keepalive: when it last showed life (ms), pings sent unanswered,
    /// when the last went out, the upload bytes seen then.
    alive_ms: u64,
    unanswered: u32,
    pinged_ms: u64,
    rx_seen: u64,
    /// G4.3cd: the blocks routed to the subscriber now.
    routes: Vec<(FramedRoute, RouteOrigin)>,
    /// G4.9b: the download queue (its profile's), `None`: policed in XDP.
    shape: Option<corerouter_hal::queue::Kind>,
    /// G4.3hd: the DHCP binding as last bound or renewed (the pair's
    /// record carries it).
    lease: Option<Lease>,
}

/// An XDP map change, for the thread (it knows the ports' index and MAC).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum XdpOp {
    Upsert {
        slot: u32,
        interface: IfName,
        client_mac: [u8; 6],
        ip: Ipv4Addr,
        up: Rate,
        down: Rate,
        shape: Option<corerouter_hal::queue::Kind>,
    },
    Remove(u32),
    /// G4.3cd: a block routed to the session at `slot`.
    Route {
        dst: IpNet,
        slot: u32,
        add: bool,
    },
}

/// G4.3cd: a kernel route of a block to an IPoE subscriber (the kernel
/// forwards IPoE downstream: `dst via ip`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KernelRoute {
    pub dst: Ipv4Net,
    pub via: Ipv4Addr,
    pub add: bool,
}

/// Per-stage attempts of a user or a MAC (`ppp.why`).
#[derive(Debug, Clone, Default)]
struct Track {
    attempts: [u32; 3],
    last_stage: Option<Stage>,
    last: Option<Box<HistoryEntry>>,
}

const STAGES: [Stage; 3] = [Stage::Dhcp, Stage::Auth, Stage::Up];

fn stage_index(s: Stage) -> usize {
    STAGES.iter().position(|x| *x == s).unwrap_or(0)
}

#[derive(Default)]
struct State {
    /// The running config's servers (by name) and `/ppp aaa`, kept fresh
    /// by the thread.
    servers: HashMap<String, DhcpServer>,
    interim_default: u32,
    /// `/ppp profile` rate limits by name (Mikrotik-Group), per refresh.
    profile_rates: HashMap<String, String>,
    /// G4.9b: each profile's download queue (`None`: the XDP policer).
    profile_shapes: HashMap<String, Option<corerouter_hal::queue::Kind>>,
    aaa: Option<Arc<dyn AaaBackend>>,
    asked: HashMap<Key, Asked>,
    inbox: Vec<(String, Vec<u8>, Verdict)>,
    authz: HashMap<Key, Authz>,
    subs: HashMap<Key, Sub>,
    active: BTreeMap<String, ActiveSession>,
    by_acct: HashMap<String, String>,
    by_id: HashMap<String, Key>,
    history: VecDeque<HistoryEntry>,
    why: HashMap<String, Track>,
    revokes: Vec<Revoke>,
    /// Why a revoked client's lease ends (the lease only says `released`).
    revoked: HashMap<Key, (&'static str, &'static str, u32)>,
    ops: Vec<XdpOp>,
    pings: Vec<(IfName, Ipv4Addr)>,
    free_slots: Vec<u32>,
    next_slot: u32,
    seq: u32,
    stats: ServiceStats,
    /// The XDP data plane takes the sessions (else: no policer).
    xdp: bool,
    /// G4.3cd: who holds each routed block (the router's table), the space
    /// no route may take, the kernel routes to make and log lines
    /// (Portuguese; error or not) for the thread.
    framed: FramedTable,
    forbidden: Arc<Forbidden>,
    kroutes: Vec<KernelRoute>,
    logs: Vec<(bool, String)>,
    /// Sessions by address (an ARP answer finds its session in O(1): the
    /// takeover pings every adopted one, G4.3hd).
    by_ip: HashMap<Ipv4Addr, Key>,
    /// G4.3hd: the redundant pair (hot standby).
    ha: ha::IpoeHa,
}

impl State {
    fn track(&mut self, key: &str) -> &mut Track {
        if !self.why.contains_key(key) && self.why.len() >= WHY_KEYS {
            self.why.clear();
        }
        self.why.entry(key.to_owned()).or_default()
    }

    fn reach(&mut self, keys: &[&str], stage: Stage) {
        // A subscriber named by its MAC is one key, not two.
        for (i, k) in keys.iter().enumerate() {
            if keys.get(..i).is_some_and(|before| before.contains(k)) {
                continue;
            }
            let t = self.track(k);
            if let Some(n) = t.attempts.get_mut(stage_index(stage)) {
                *n = n.saturating_add(1);
            }
            t.last_stage = Some(stage);
        }
    }

    fn record(&mut self, keys: &[&str], h: HistoryEntry) {
        for (i, k) in keys.iter().enumerate() {
            if keys.get(..i).is_some_and(|before| before.contains(k)) {
                continue;
            }
            let t = self.track(k);
            if let Some(st) = h.stage {
                t.last_stage = Some(st);
            }
            if h.event != "up" {
                t.last = Some(Box::new(h.clone()));
            }
        }
        if self.history.len() >= HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(h);
    }

    fn slot(&mut self) -> Option<u32> {
        if let Some(s) = self.free_slots.pop() {
            return Some(s);
        }
        let used = SLOT_TOP.saturating_sub(self.next_slot);
        if used >= SLOTS {
            return None;
        }
        let s = self.next_slot;
        self.next_slot = self.next_slot.saturating_sub(1);
        Some(s)
    }
}

/// The core, shared by the engine's calls, the thread and RADIUS.
pub(crate) struct Core {
    st: Mutex<State>,
    /// Monotonic milliseconds (the keepalive, the RADIUS grace).
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

/// What [`Core::bound`] decided to send to RADIUS once the lock is let go.
struct AcctOut {
    req: AcctRequest,
    source: Option<Arc<dyn AcctSource>>,
}

fn mac_text(m: [u8; 6]) -> String {
    MacAddr(m).to_string()
}

/// The enabled `/ppp secret` (service `ipoe`) of `user` (O(1): the
/// engine's index).
fn secret<'a>(view: &IpoeView<'a>, user: &str) -> Option<&'a corerouter_model::ppp::PppSecret> {
    view.secret(user).filter(|s| !s.disabled)
}

/// RouterOS rate-limit text → the XDP policer's two directions (rx = from
/// the subscriber).
pub(crate) fn rates(text: Option<&str>) -> (Rate, Rate) {
    let Some(r) = text.and_then(|t| t.parse::<RateLimit>().ok()) else {
        return (Rate::default(), Rate::default());
    };
    let dir = |up: bool| {
        let pick = |p: corerouter_proto_radius::rate_limit::Pair<u64>| if up { p.rx } else { p.tx };
        Rate {
            rate_bps: pick(r.rate),
            burst_bps: r.burst_rate.map_or(0, pick),
            threshold_bps: r.burst_threshold.map_or(0, pick),
            burst_secs: r.burst_time.map_or(0, |t| if up { t.rx } else { t.tx }),
        }
    };
    (dir(true), dir(false))
}

/// What an Access-Accept says, as a grant for the DHCP server and what the
/// session keeps (RouterOS' DHCP attributes: Framed-IP-Address,
/// Framed-Pool, Session-Timeout as the lease time, Mikrotik-Rate-Limit or
/// Ascend-Data-Rate/Ascend-Xmit-Rate, Mikrotik-Address-List,
/// Mikrotik-Group, Acct-Interim-Interval, Class).
fn accept(
    reply: &AuthReply,
    user: &str,
    cfg_profile: impl Fn(&str) -> Option<String>,
) -> (Grant, Authz) {
    let attr = |name: &str| {
        reply
            .attributes
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.value.clone())
    };
    let profile = attr("Mikrotik-Group").unwrap_or_else(|| DEFAULT_PROFILE.into());
    let ascend = match (attr("Ascend-Xmit-Rate"), attr("Ascend-Data-Rate")) {
        // Ascend-Data-Rate is the download (tx), Xmit the upload (rx).
        (Some(up), Some(down)) => Some(format!("{up}/{down}")),
        (None, Some(down)) => Some(format!("{down}/{down}")),
        _ => None,
    };
    let rate = attr("Mikrotik-Rate-Limit")
        .or(ascend)
        .filter(|r| r.parse::<RateLimit>().is_ok())
        .or_else(|| cfg_profile(&profile));
    let mut g = Grant {
        address: attr("Framed-IP-Address").and_then(|v| v.parse().ok()),
        pool: attr("Framed-Pool"),
        lease_time: attr("Session-Timeout").and_then(|v| v.parse().ok()),
        address_lists: Vec::new(),
    };
    if let Some(l) = attr("Mikrotik-Address-List")
        .filter(|l| l.parse::<corerouter_model::firewall::Name>().is_ok())
    {
        g.address_lists.push(l);
    }
    let (routes, refused) = framed::from_radius(
        reply
            .attributes
            .iter()
            .map(|a| (a.name.as_str(), a.value.as_str())),
    );
    let a = Authz {
        user: user.to_owned(),
        radius: true,
        rate,
        interim: attr("Acct-Interim-Interval").and_then(|v| v.parse().ok()),
        class: corerouter_engine::radius::reply_classes(reply),
        profile,
        routes,
        refused,
    };
    (g, a)
}

/// Why a lease ended, for people: (reason key, hint in Portuguese,
/// Acct-Terminate-Cause).
fn explain(state: &str) -> (&'static str, &'static str, u32) {
    match state {
        "released" => (
            "released",
            "o CPE liberou o endereço (DHCPRELEASE): foi desligado com calma ou trocou de rede",
            cause::USER_REQUEST,
        ),
        "expired" => (
            "lease-expired",
            "o CPE parou de renovar o lease: desligado, cabo, ONU ou VLAN caídos",
            cause::LOST_CARRIER,
        ),
        "declined" | "conflict" => (
            "address-conflict",
            "o CPE recusou o endereço (DHCPDECLINE): outro aparelho na rede usa o mesmo IP",
            cause::LOST_SERVICE,
        ),
        _ => (
            "ended",
            "o lease acabou no servidor DHCP (servidor removido ou desligado)",
            cause::LOST_SERVICE,
        ),
    }
}

impl Core {
    pub(crate) fn new() -> Arc<Self> {
        let t0 = Instant::now();
        Self::with_clock(Box::new(move || {
            u64::try_from(t0.elapsed().as_millis()).unwrap_or(u64::MAX)
        }))
    }

    /// With another clock (the tests' simulated one).
    pub(crate) fn with_clock(clock: Box<dyn Fn() -> u64 + Send + Sync>) -> Arc<Self> {
        Arc::new(Core {
            st: Mutex::new(State {
                next_slot: SLOT_TOP,
                // Silent until the config says whether a pair runs
                // (G4.3hd: a standby must not answer its first second).
                ha: ha::IpoeHa::silent(),
                ..State::default()
            }),
            clock,
        })
    }

    fn ms(&self) -> u64 {
        (self.clock)()
    }

    /// The running config the engine's calls need (the thread, once a
    /// second).
    pub(crate) fn configure(&self, cfg: &Config, aaa: Option<Arc<dyn AaaBackend>>) {
        let mut st = guard(&self.st);
        st.servers = cfg
            .ip
            .dhcp_server
            .servers
            .iter()
            .filter(|s| !s.disabled && s.sessions())
            .map(|s| (s.name.clone(), s.clone()))
            .collect();
        st.interim_default = cfg.ppp.aaa.interim_update;
        st.profile_rates = cfg
            .ppp
            .profiles
            .iter()
            .filter_map(|p| p.rate_limit.clone().map(|r| (p.name.clone(), r)))
            .collect();
        st.profile_shapes = cfg
            .ppp
            .all_profiles()
            .into_iter()
            .map(|p| {
                let e = cfg.ppp.effective(None, &p.name, DEFAULT_PROFILE);
                (p.name, corerouter_engine::queue::shape_of(&cfg.queue, &e))
            })
            .collect();
        st.aaa = aaa;
        st.forbidden = Arc::new(Forbidden::of(cfg));
        let r = &cfg.ppp.redundancy;
        st.ha.enabled = r.enabled;
        st.ha.hot = r.enabled && r.mode == corerouter_model::ppp_redundancy::HaMode::HotStandby;
    }

    /// G4.3cd: the router's table of routed blocks (shared with PPPoE and
    /// the commands); what a previous run of the service held is gone.
    pub(crate) fn set_framed(&self, table: FramedTable) {
        table.forget("ipoe");
        guard(&self.st).framed = table;
    }

    /// Kernel routes of routed blocks to make (`dst via subscriber`).
    pub(crate) fn take_kernel_routes(&self) -> Vec<KernelRoute> {
        std::mem::take(&mut guard(&self.st).kroutes)
    }

    /// Log lines for the router's log: (error, Portuguese text).
    pub(crate) fn take_logs(&self) -> Vec<(bool, String)> {
        std::mem::take(&mut guard(&self.st).logs)
    }

    /// The interfaces of the session servers (the XDP access ports).
    pub(crate) fn ports(&self) -> Vec<IfName> {
        let st = guard(&self.st);
        let mut v: Vec<IfName> = st.servers.values().map(|s| s.interface.clone()).collect();
        v.sort();
        v.dedup();
        v
    }

    /// The XDP data plane came (all sessions go in) or went.
    pub(crate) fn set_xdp(&self, on: bool) {
        let mut st = guard(&self.st);
        if st.xdp == on {
            return;
        }
        st.xdp = on;
        st.stats.dataplane = on;
        if !on {
            return;
        }
        let subs: Vec<Sub> = st.subs.values().cloned().collect();
        for s in subs {
            let slot = match s.slot {
                Some(x) => Some(x),
                None => st.slot(),
            };
            if let Some(slot) = slot {
                let (up, down) = rates(s.rate.as_deref());
                st.ops.push(XdpOp::Upsert {
                    slot,
                    interface: s.interface.clone(),
                    client_mac: s.mac,
                    ip: s.ip,
                    up,
                    down,
                    shape: s.shape,
                });
                if let Some(x) = st.subs.get_mut(&s.key) {
                    x.slot = Some(slot);
                }
                for (r, _) in &s.routes {
                    st.ops.push(XdpOp::Route {
                        dst: r.dst,
                        slot,
                        add: true,
                    });
                }
            }
        }
    }

    pub(crate) fn take_ops(&self) -> Vec<XdpOp> {
        std::mem::take(&mut guard(&self.st).ops)
    }

    /// The XDP slots in use, for the counters.
    pub(crate) fn slots(&self) -> Vec<u32> {
        guard(&self.st)
            .subs
            .values()
            .filter_map(|s| s.slot)
            .collect()
    }

    /// The XDP counters of the last second (`secs` since the last call).
    pub(crate) fn counters(&self, c: &[(u32, PppoeCounters)], secs: u64) {
        let mut st = guard(&self.st);
        let by_slot: HashMap<u32, String> = st
            .subs
            .values()
            .filter_map(|s| s.slot.map(|x| (x, s.id.clone())))
            .collect();
        for (slot, n) in c {
            let Some(id) = by_slot.get(slot) else {
                continue;
            };
            if let Some(a) = st.active.get_mut(id) {
                let d = secs.max(1);
                a.rx_bps = n.up_bytes.saturating_sub(a.rx_bytes).saturating_mul(8) / d;
                a.tx_bps = n.down_bytes.saturating_sub(a.tx_bytes).saturating_mul(8) / d;
                a.rx_bytes = n.up_bytes;
                a.tx_bytes = n.down_bytes;
                a.rx_packets = n.up_packets;
                a.tx_packets = n.down_packets;
                a.queue_us = n.down_queue_us;
                a.drops = n.up_policed + n.down_policed;
            }
        }
        let now = self.ms();
        st.ha_counters(now);
    }

    /// Keepalive (TR-146 R-92): ping the silent, end the ones that never
    /// answer. Life is upload traffic (XDP counters), an ARP answer or a
    /// DHCP renewal.
    pub(crate) fn keepalive(&self) {
        let now = self.ms();
        let mut st = guard(&self.st);
        let mut dead = Vec::new();
        let mut pings = Vec::new();
        let rx: HashMap<String, u64> = st
            .active
            .iter()
            .map(|(id, a)| (id.clone(), a.rx_bytes))
            .collect();
        for s in st.subs.values_mut() {
            let Some(k) = s.keepalive else { continue };
            let seen = rx.get(&s.id).copied().unwrap_or(0);
            if seen != s.rx_seen {
                s.rx_seen = seen;
                s.alive_ms = now;
                s.unanswered = 0;
            }
            if now.saturating_sub(s.alive_ms) < u64::from(k) * 1000
                || now.saturating_sub(s.pinged_ms) < PING_EVERY_MS
            {
                continue;
            }
            if s.unanswered >= PING_TRIES {
                dead.push(s.key.clone());
                continue;
            }
            s.unanswered += 1;
            s.pinged_ms = now;
            pings.push((s.interface.clone(), s.ip));
        }
        st.pings.extend(pings);
        for k in dead {
            if st.revoked.contains_key(&k) {
                continue;
            }
            st.revoked.insert(
                k.clone(),
                (
                    "keepalive",
                    "o CPE não respondeu a 3 pings ARP: está desligado, sem link ou travado",
                    cause::LOST_CARRIER,
                ),
            );
            st.revokes.push(Revoke {
                server: k.0.clone(),
                client_key: k.1.clone(),
                why: "keepalive: no ARP reply".into(),
            });
        }
    }

    /// The answer of a RADIUS ask (the AAA driver's thread).
    fn answered(&self, key: Key, reply: AuthReply) {
        let now = self.ms();
        let mut st = guard(&self.st);
        let Some(asked) = st.asked.remove(&key) else {
            return;
        };
        if now.saturating_sub(asked.at_ms) > ASK_GRACE_MS {
            return;
        }
        let verdict = match reply.outcome {
            AuthOutcome::Accept => {
                let (g, a) = accept(&reply, &asked.user, |p| st.profile_rates.get(p).cloned());
                st.stats.auth_accept += 1;
                st.authz.insert(key.clone(), a);
                Verdict::Accept(g)
            }
            other => {
                st.stats.auth_reject += 1;
                // The server's own words (Reply-Message), when it sent some.
                let said = reply
                    .attributes
                    .iter()
                    .find(|a| a.name == "Reply-Message")
                    .map(|a| a.value.clone())
                    .or_else(|| reply.message.clone())
                    .filter(|m| !m.is_empty());
                let why = said.clone().unwrap_or_else(|| match other {
                    AuthOutcome::Reject | AuthOutcome::Challenge => "rejected by RADIUS".into(),
                    _ => "RADIUS did not answer".into(),
                });
                let mac = asked.mac.clone();
                let (reason, hint) = if matches!(
                    other,
                    AuthOutcome::Reject | AuthOutcome::Challenge
                ) {
                    (
                        "rejected",
                        "o RADIUS recusou este cliente: confira o cadastro do MAC ou do circuito (User-Name)",
                    )
                } else {
                    (
                        "radius-timeout",
                        "o RADIUS não respondeu: veja /radius monitor (servidor, segredo, firewall)",
                    )
                };
                let h = HistoryEntry {
                    at: unix_now(),
                    name: asked.user.clone(),
                    caller_id: mac.clone(),
                    server: key.0.clone(),
                    event: "failed".into(),
                    stage: Some(Stage::Auth),
                    reason: reason.into(),
                    hint: hint.into(),
                    reply_message: said,
                    ..HistoryEntry::default()
                };
                st.record(&[&asked.user, &mac], h);
                Verdict::Reject(why)
            }
        };
        st.inbox.push((key.0, key.1, verdict));
    }

    /// A lease of a session server was bound or renewed.
    fn bound(self: &Arc<Self>, b: &Binding, view: &IpoeView<'_>) -> Option<AcctOut> {
        let l = &b.lease;
        let key: Key = (l.server.clone(), l.client_key());
        let now = self.ms();
        let mut st = guard(&self.st);
        let srv = st.servers.get(&l.server).cloned()?;
        if let Some(s) = st.subs.get_mut(&key)
            && s.ip == l.address
        {
            // A renewal: proof of life (and the pair's copy of the lease).
            s.alive_ms = now;
            s.unanswered = 0;
            s.lease = Some(l.clone());
            st.ha_dirty(&key);
            return None;
        }
        // A new address for a client that had one: the old session ends.
        let mut out = None;
        if st.subs.contains_key(&key) {
            out = self.end_locked(
                &mut st,
                &key,
                (
                    "replaced",
                    "o CPE recebeu outro endereço no mesmo servidor",
                    cause::LOST_SERVICE,
                ),
            );
        }
        let circuit = l
            .relay_info
            .as_deref()
            .and_then(|r| agent::get(r, agent::CIRCUIT_ID))
            .map(agent::text);
        let remote = l
            .relay_info
            .as_deref()
            .and_then(|r| agent::get(r, agent::REMOTE_ID))
            .map(agent::text);
        let authz = st.authz.remove(&key);
        let user = authz
            .as_ref()
            .map(|a| a.user.clone())
            .or_else(|| {
                user_of(
                    &srv,
                    l.mac,
                    circuit.as_deref().map(str::as_bytes),
                    remote.as_deref().map(str::as_bytes),
                )
            })
            .unwrap_or_else(|| mac_text(l.mac));
        // The rate: RADIUS, then the static lease's, then the secret's
        // profile.
        let cfg = view.cfg;
        let lease_rate = view.lease_rate(l.address).map(str::to_owned);
        let sec = secret(view, &user);
        let profile = sec.map(|s| s.profile.clone()).filter(|p| !p.is_empty());
        let secret_rate = sec.and_then(|s| {
            cfg.ppp
                .effective(Some(s), &s.profile, DEFAULT_PROFILE)
                .rate_limit
        });
        let rate = authz
            .as_ref()
            .and_then(|a| a.rate.clone())
            .or(lease_rate)
            .or(secret_rate);
        st.seq = st.seq.wrapping_add(1);
        let unix = unix_now();
        let id = format!("*i{:x}", st.seq);
        let acct_id = format!("{:08X}{:04X}", unix as u32, st.seq as u16);
        let radius = authz.as_ref().is_some_and(|a| a.radius);
        let slot = if st.xdp { st.slot() } else { None };
        // G4.3cd: the routed blocks, from RADIUS or the secret.
        let (want, mut refused) = match authz.as_ref() {
            Some(a) if a.radius => (a.routes.clone(), a.refused.clone()),
            _ => (
                sec.map(|s| s.routes.iter().map(|r| (*r, RouteOrigin::Secret)).collect())
                    .unwrap_or_default(),
                Vec::new(),
            ),
        };
        let holder = Holder {
            session: id.clone(),
            user: user.clone(),
            origin: RouteOrigin::Secret,
            lane: 0,
            service: "ipoe",
        };
        let adm = framed::admit(
            &st.framed,
            &st.forbidden,
            &want,
            &holder,
            Some(l.address),
            Some(NO_V6),
        );
        refused.extend(adm.refused.iter().cloned());
        let route_rows = adm.rows();
        let a = ActiveSession {
            id: id.clone(),
            name: user.clone(),
            service: "ipoe".into(),
            caller_id: mac_text(l.mac),
            address: Some(l.address),
            server: l.server.clone(),
            interface: srv.interface.to_string(),
            circuit_id: circuit.clone(),
            remote_id: remote.clone(),
            rate_limit: rate.clone(),
            profile: authz
                .as_ref()
                .map(|a| a.profile.clone())
                .or(profile)
                .unwrap_or_else(|| DEFAULT_PROFILE.into()),
            encoding: "dhcp".into(),
            radius,
            mtu: 1500,
            routes: route_rows.clone(),
            refused_routes: refused.clone(),
            ..ActiveSession::default()
        };
        let sub = Sub {
            id: id.clone(),
            key: key.clone(),
            user: user.clone(),
            ip: l.address,
            mac: l.mac,
            server: l.server.clone(),
            interface: srv.interface.clone(),
            slot,
            rate: rate.clone(),
            acct: srv.use_radius != UseRadius::No,
            acct_id: acct_id.clone(),
            interim: authz.as_ref().and_then(|a| a.interim),
            class: authz.as_ref().map(|a| a.class.clone()).unwrap_or_default(),
            up_at: unix,
            keepalive: srv.ipoe_keepalive,
            alive_ms: now,
            unanswered: 0,
            pinged_ms: 0,
            rx_seen: 0,
            routes: adm.routes.clone(),
            shape: st
                .profile_shapes
                .get(&a.profile)
                .copied()
                .unwrap_or_else(|| st.profile_shapes.get(DEFAULT_PROFILE).copied().flatten()),
            lease: Some(l.clone()),
        };
        if let Some(slot) = slot {
            let (up, down) = rates(rate.as_deref());
            st.ops.push(XdpOp::Upsert {
                slot,
                interface: srv.interface.clone(),
                client_mac: l.mac,
                ip: l.address,
                up,
                down,
                shape: sub.shape,
            });
        }
        // After the session's entry: the LPM (with XDP) and, always, the
        // kernel route (the kernel forwards IPoE downstream).
        for (r, _) in &adm.routes {
            if let Some(slot) = slot {
                st.ops.push(XdpOp::Route {
                    dst: r.dst,
                    slot,
                    add: true,
                });
            }
            if let IpNet::V4(dst) = r.dst {
                st.kroutes.push(KernelRoute {
                    dst,
                    via: l.address,
                    add: true,
                });
            }
        }
        for row in &route_rows {
            st.logs.push((
                false,
                format!("IPoE: {user}: rota {} ({})", row.route, row.origin.label()),
            ));
        }
        for why in &refused {
            st.logs
                .push((true, format!("IPoE: {user}: rota recusada: {why}")));
        }
        let mac = mac_text(l.mac);
        st.reach(&[&user, &mac], Stage::Up);
        st.record(
            &[&user, &mac],
            HistoryEntry {
                at: unix,
                name: user.clone(),
                caller_id: mac.clone(),
                server: l.server.clone(),
                event: "up".into(),
                stage: Some(Stage::Up),
                address: Some(l.address),
                routes: route_rows,
                refused_routes: refused,
                ..HistoryEntry::default()
            },
        );
        st.active.insert(id.clone(), a);
        st.by_acct.insert(acct_id.clone(), id.clone());
        st.by_id.insert(id.clone(), key.clone());
        let acct = sub.acct;
        let interim = sub
            .interim
            .or((st.interim_default > 0).then_some(st.interim_default));
        let class = sub.class.clone();
        st.by_ip.insert(l.address, key.clone());
        st.ha_dirty(&key);
        st.subs.insert(key, sub);
        let aaa = st.aaa.clone();
        drop(st);
        if !acct || aaa.is_none() {
            return out;
        }
        let src: Arc<dyn AcctSource> = Arc::new(Counters {
            core: self.clone(),
            id: id.clone(),
        });
        let req = AcctRequest {
            service: AaaService::Dhcp,
            status: AcctStatus::Start,
            session_id: acct_id,
            user,
            counters: None,
            terminate_cause: None,
            interim_secs: interim,
            attributes: {
                let mut v = acct_attributes(
                    l.address,
                    &mac,
                    &srv.interface,
                    circuit.as_deref(),
                    remote.as_deref(),
                );
                v.extend(route_attributes(&adm.routes));
                v
            },
            class,
        };
        // An old session's Stop first (it went out of the lock already, as `out`).
        if let Some(o) = out
            && let Some(a) = &aaa
        {
            let _ = a.account(o.req, o.source);
        }
        Some(AcctOut {
            req,
            source: Some(src),
        })
    }

    /// End the session of `key` (under the lock): the XDP slot, the active
    /// row, history and why; returns the Accounting-Stop to send.
    fn end_locked(
        &self,
        st: &mut State,
        key: &Key,
        why: (&'static str, &'static str, u32),
    ) -> Option<AcctOut> {
        let s = st.subs.remove(key)?;
        if st.by_ip.get(&s.ip) == Some(key) {
            st.by_ip.remove(&s.ip);
        }
        st.ha_gone(key);
        // G4.3cd: the blocks go before the session (a block left behind
        // is a blackhole).
        for (r, _) in &s.routes {
            if let Some(slot) = s.slot {
                st.ops.push(XdpOp::Route {
                    dst: r.dst,
                    slot,
                    add: false,
                });
            }
            if let IpNet::V4(dst) = r.dst {
                st.kroutes.push(KernelRoute {
                    dst,
                    via: s.ip,
                    add: false,
                });
            }
        }
        framed::release_all(&st.framed, &s.routes, &s.id);
        if !s.routes.is_empty() {
            st.logs.push((
                false,
                format!("IPoE: {}: {} rota(s) removida(s)", s.user, s.routes.len()),
            ));
        }
        if let Some(slot) = s.slot {
            st.ops.push(XdpOp::Remove(slot));
            st.free_slots.push(slot);
        }
        let a = st.active.remove(&s.id);
        st.by_acct.remove(&s.acct_id);
        st.by_id.remove(&s.id);
        let unix = unix_now();
        let mac = mac_text(s.mac);
        let (reason, hint, cause) = why;
        let uptime = unix.saturating_sub(s.up_at);
        st.record(
            &[&s.user, &mac],
            HistoryEntry {
                at: unix,
                name: s.user.clone(),
                caller_id: mac.clone(),
                server: s.server.clone(),
                event: "down".into(),
                stage: Some(Stage::Up),
                reason: reason.into(),
                hint: hint.into(),
                address: Some(s.ip),
                uptime_secs: uptime,
                rx_bytes: a.as_ref().map_or(0, |a| a.rx_bytes),
                tx_bytes: a.as_ref().map_or(0, |a| a.tx_bytes),
                routes: a.as_ref().map(|a| a.routes.clone()).unwrap_or_default(),
                ..HistoryEntry::default()
            },
        );
        if !s.acct {
            return None;
        }
        st.aaa.as_ref()?;
        let counters = a.as_ref().map(|a| AcctCounters {
            input_octets: a.rx_bytes,
            output_octets: a.tx_bytes,
            input_packets: a.rx_packets,
            output_packets: a.tx_packets,
            session_time: u32::try_from(uptime).unwrap_or(u32::MAX),
        });
        Some(AcctOut {
            req: AcctRequest {
                service: AaaService::Dhcp,
                status: AcctStatus::Stop,
                session_id: s.acct_id,
                user: s.user,
                counters,
                terminate_cause: Some(cause),
                interim_secs: None,
                attributes: {
                    let mut v = acct_attributes(s.ip, &mac, &s.interface, None, None);
                    v.extend(route_attributes(&s.routes));
                    v
                },
                class: s.class,
            },
            source: None,
        })
    }

    fn gone(&self, l: &Lease, state: &str) -> Option<AcctOut> {
        let key: Key = (l.server.clone(), l.client_key());
        let mut st = guard(&self.st);
        if st.subs.get(&key).is_none_or(|s| s.ip != l.address) {
            return None;
        }
        let why = st.revoked.remove(&key).unwrap_or_else(|| explain(state));
        self.end_locked(&mut st, &key, why)
    }

    /// Ask the DHCP server to end these sessions (`ppp.active.remove`, a
    /// Disconnect-Request): their leases end, the clients start over.
    fn revoke(&self, ids: &[String], why: (&'static str, &'static str, u32), text: &str) -> usize {
        let mut st = guard(&self.st);
        let mut n = 0;
        for id in ids {
            let Some(k) = st.by_id.get(id).cloned() else {
                continue;
            };
            n += 1;
            if st.revoked.contains_key(&k) {
                continue;
            }
            st.revoked.insert(k.clone(), why);
            st.revokes.push(Revoke {
                server: k.0,
                client_key: k.1,
                why: text.into(),
            });
        }
        n
    }

    /// The local verdict, or the RADIUS ask (sent once the lock is let go).
    fn authorize(self: &Arc<Self>, ask: &AuthAsk, view: &IpoeView<'_>) -> Option<Verdict> {
        let cfg = view.cfg;
        let key: Key = (ask.server.clone(), ask.client_key.clone());
        let mac = mac_text(ask.mac);
        let local = local_verdict(ask, view);
        let mut st = guard(&self.st);
        st.reach(&[&mac], Stage::Dhcp);
        let user = match local {
            Local::Done(v) => {
                let user = cfg
                    .ip
                    .dhcp_server
                    .server(&ask.server)
                    .and_then(|s| {
                        user_of(
                            s,
                            ask.mac,
                            ask.circuit_id.as_deref(),
                            ask.remote_id.as_deref(),
                        )
                    })
                    .unwrap_or_else(|| mac.clone());
                match &v {
                    Verdict::Accept(_) => {
                        st.stats.auth_accept += 1;
                        let profile = secret(view, &user)
                            .map(|s| s.profile.clone())
                            .unwrap_or_else(|| DEFAULT_PROFILE.into());
                        st.authz.insert(
                            key,
                            Authz {
                                user,
                                profile,
                                ..Authz::default()
                            },
                        );
                    }
                    Verdict::Reject(why) => {
                        st.stats.auth_reject += 1;
                        let h = HistoryEntry {
                            at: unix_now(),
                            name: user.clone(),
                            caller_id: mac.clone(),
                            server: ask.server.clone(),
                            event: "failed".into(),
                            stage: Some(Stage::Auth),
                            reason: "not-authorized".into(),
                            hint: "nenhum /ppp secret service=ipoe com este nome e ipoe_unknown=reject: cadastre o MAC ou o circuito".into(),
                            reply_message: Some(why.clone()),
                            ..HistoryEntry::default()
                        };
                        st.record(&[&user, &mac], h);
                    }
                }
                return Some(v);
            }
            Local::AskRadius { user } => user,
        };
        let Some(aaa) = st.aaa.clone() else {
            st.stats.auth_reject += 1;
            return Some(Verdict::Reject("no RADIUS service".into()));
        };
        if st.asked.contains_key(&key) {
            return None;
        }
        if st.asked.len() >= MAX_ASKED {
            let now = self.ms();
            st.asked
                .retain(|_, a| now.saturating_sub(a.at_ms) <= ASK_GRACE_MS);
            if st.asked.len() >= MAX_ASKED {
                return None;
            }
        }
        st.reach(&[&user, &mac], Stage::Auth);
        st.asked.insert(
            key.clone(),
            Asked {
                at_ms: self.ms(),
                user: user.clone(),
                mac: mac.clone(),
            },
        );
        drop(st);
        let srv = cfg.ip.dhcp_server.server(&ask.server);
        let nas_port_id = match (&ask.circuit_id, cfg.ppp.aaa.use_circuit_id_in_nas_port_id) {
            (Some(c), true) => agent::text(c),
            _ => srv.map(|s| s.interface.to_string()).unwrap_or_default(),
        };
        let mut attributes = vec![Attribute::new("NAS-Port-Type", NAS_PORT_ETHERNET)];
        // RFC 4679 §3: the access line, as the relay agent named it.
        if let Some(c) = &ask.circuit_id {
            attributes.push(Attribute::new("ADSL-Agent-Circuit-Id", agent::text(c)));
        }
        if let Some(r) = &ask.remote_id {
            attributes.push(Attribute::new("ADSL-Agent-Remote-Id", agent::text(r)));
        }
        let req = AuthRequest {
            service: AaaService::Dhcp,
            user,
            // RouterOS: an empty password.
            credentials: Credentials::Pap {
                password: String::new(),
            },
            nas_port_id: Some(nas_port_id),
            nas_port: None,
            calling_station_id: Some(mac),
            called_station_id: Some(ask.server.clone()),
            attributes,
        };
        let me = self.clone();
        // The callback runs on the RADIUS driver's thread: it only parses
        // the reply and queues the verdict (`answered`).
        aaa.authenticate(req, Box::new(move |reply| me.answered(key, reply)));
        None
    }
}

fn acct_attributes(
    ip: Ipv4Addr,
    mac: &str,
    interface: &IfName,
    circuit: Option<&str>,
    remote: Option<&str>,
) -> Vec<Attribute> {
    let mut v = vec![
        Attribute::new("Framed-IP-Address", ip.to_string()),
        Attribute::new("Calling-Station-Id", mac),
        Attribute::new("NAS-Port-Id", interface.to_string()),
        Attribute::new("NAS-Port-Type", NAS_PORT_ETHERNET),
    ];
    if let Some(c) = circuit {
        v.push(Attribute::new("ADSL-Agent-Circuit-Id", c));
    }
    if let Some(r) = remote {
        v.push(Attribute::new("ADSL-Agent-Remote-Id", r));
    }
    v
}

/// Counters of one session for the RADIUS interims.
struct Counters {
    core: Arc<Core>,
    id: String,
}

impl AcctSource for Counters {
    fn counters(&self) -> Option<AcctCounters> {
        let st = guard(&self.core.st);
        let a = st.active.get(&self.id)?;
        let s = st.by_id.get(&self.id).and_then(|k| st.subs.get(k))?;
        Some(AcctCounters {
            input_octets: a.rx_bytes,
            output_octets: a.tx_bytes,
            input_packets: a.rx_packets,
            output_packets: a.tx_packets,
            session_time: u32::try_from(unix_now().saturating_sub(s.up_at)).unwrap_or(u32::MAX),
        })
    }
}

/// The engine's `IpoeBackend`.
pub(crate) struct Backend(pub Arc<Core>);

impl Backend {
    fn send(&self, out: Option<AcctOut>) {
        let Some(o) = out else { return };
        let aaa = guard(&self.0.st).aaa.clone();
        if let Some(a) = aaa
            && let Err(e) = a.account(o.req, o.source)
        {
            log::warn!("ipoe: accounting not sent: {e}");
        }
    }
}

impl IpoeBackend for Backend {
    fn authorize(&self, ask: &AuthAsk, view: &IpoeView<'_>) -> Option<Verdict> {
        self.0.authorize(ask, view)
    }

    fn verdicts(&self) -> Vec<(String, Vec<u8>, Verdict)> {
        std::mem::take(&mut guard(&self.0.st).inbox)
    }

    fn bound(&self, b: &Binding, view: &IpoeView<'_>) {
        let out = self.0.bound(b, view);
        self.send(out);
    }

    fn gone(&self, lease: &Lease, why: &str) {
        let out = self.0.gone(lease, why);
        self.send(out);
    }

    fn revokes(&self) -> Vec<Revoke> {
        std::mem::take(&mut guard(&self.0.st).revokes)
    }

    fn pings(&self) -> Vec<(IfName, Ipv4Addr)> {
        std::mem::take(&mut guard(&self.0.st).pings)
    }

    fn arp_reply(&self, interface: &IfName, ip: Ipv4Addr, mac: [u8; 6]) {
        let now = self.0.ms();
        let mut st = guard(&self.0.st);
        let Some(key) = st.by_ip.get(&ip).cloned() else {
            return;
        };
        if let Some(s) = st
            .subs
            .get_mut(&key)
            .filter(|s| s.mac == mac && s.interface == *interface)
        {
            s.alive_ms = now;
            s.unanswered = 0;
        }
    }

    fn answering(&self) -> bool {
        let st = guard(&self.0.st);
        // G4.3hk: as `pppoe_bng::may_answer` (this file stands alone in
        // its bench): no pair here and none in `ppp-ha`, or the active.
        if st.ha.enabled {
            st.ha.answering
        } else {
            !st.ha.paired
        }
    }

    fn takeover(&self) -> Option<(Vec<String>, Vec<Lease>)> {
        guard(&self.0.st).ha.leases.take()
    }
}

/// What `ppp.active`, `ppp.why` and `ppp.history` read.
pub(crate) struct Sessions(pub Arc<Core>);

impl PppBackend for Sessions {
    fn active(&self) -> Vec<ActiveSession> {
        let st = guard(&self.0.st);
        let now = unix_now();
        st.active
            .values()
            .map(|a| {
                let mut a = a.clone();
                if let Some(s) = st.by_id.get(&a.id).and_then(|k| st.subs.get(k)) {
                    a.uptime_secs = now.saturating_sub(s.up_at);
                }
                a
            })
            .collect()
    }

    /// Only the page is copied (100 000 sessions up: the whole table per
    /// GUI refresh held the engine lock for ~50 ms, G4.3g).
    fn active_page(
        &self,
        keep: &dyn Fn(&ActiveSession) -> bool,
        limit: usize,
    ) -> (usize, Vec<ActiveSession>) {
        let st = guard(&self.0.st);
        let now = unix_now();
        let mut hits: Vec<&ActiveSession> = st.active.values().filter(|a| keep(a)).collect();
        let total = hits.len();
        let by = |a: &&ActiveSession, b: &&ActiveSession| a.name.cmp(&b.name).then(a.id.cmp(&b.id));
        if hits.len() > limit && limit > 0 {
            hits.select_nth_unstable_by(limit - 1, by);
            hits.truncate(limit);
        } else {
            hits.truncate(limit);
        }
        hits.sort_by(by);
        let page = hits
            .into_iter()
            .map(|a| {
                let mut a = a.clone();
                if let Some(s) = st.by_id.get(&a.id).and_then(|k| st.subs.get(k)) {
                    a.uptime_secs = now.saturating_sub(s.up_at);
                }
                a
            })
            .collect();
        (total, page)
    }

    fn session(&self, id: &str) -> Option<ActiveSession> {
        let st = guard(&self.0.st);
        let mut a = st.active.get(id)?.clone();
        if let Some(s) = st.by_id.get(id).and_then(|k| st.subs.get(k)) {
            a.uptime_secs = unix_now().saturating_sub(s.up_at);
        }
        Some(a)
    }

    fn sessions_by_server(&self) -> std::collections::BTreeMap<String, usize> {
        let st = guard(&self.0.st);
        let mut m = std::collections::BTreeMap::new();
        for a in st.active.values() {
            *m.entry(a.server.clone()).or_insert(0) += 1;
        }
        m
    }

    fn terminate(&self, ids: &[String]) -> usize {
        self.0.revoke(
            ids,
            (
                "admin-reset",
                "derrubado pelo operador (ppp.active.remove): o CPE pede DHCP de novo e volta",
                cause::ADMIN_RESET,
            ),
            "disconnected by the operator",
        )
    }

    fn history(&self) -> Vec<HistoryEntry> {
        guard(&self.0.st).history.iter().cloned().collect()
    }

    fn why(&self, name: Option<&str>, mac: Option<MacAddr>) -> Why {
        let st = guard(&self.0.st);
        let key = name
            .map(str::to_owned)
            .or_else(|| mac.map(|m| m.to_string()))
            .unwrap_or_default();
        let active = st
            .active
            .values()
            .find(|a| {
                name.is_some_and(|n| a.name == n)
                    || mac.is_some_and(|m| a.caller_id == m.to_string())
            })
            .map(|a| a.id.clone());
        let mut t = st.why.get(&key).cloned().unwrap_or_default();
        // The DHCP stage is the MAC's (the name is known only after it).
        if name.is_some()
            && let Some(m) = t.last.as_ref().map(|l| l.caller_id.clone())
            && let Some(by_mac) = st.why.get(&m)
            && let (Some(n), Some(slot)) = (by_mac.attempts.first(), t.attempts.first_mut())
        {
            *slot = *n;
        }
        Why {
            query: key,
            active,
            attempts: STAGES
                .iter()
                .copied()
                .zip(t.attempts)
                .filter(|(_, n)| *n > 0)
                .collect(),
            last_stage: t.last_stage,
            last: t.last.map(|b| *b),
        }
    }

    fn stats(&self) -> ServiceStats {
        let st = guard(&self.0.st);
        let mut s = st.stats.clone();
        s.sessions = st.active.len() as u64;
        s
    }

    fn who(&self, ip: Ipv4Addr) -> Option<String> {
        self.who_vlan(ip).map(|(n, _)| n)
    }

    /// By the address index (O(1)): the old scan of every session cost
    /// O(n) per lookup, and the CGNAT exporter asks once per port block
    /// (G4.4j).
    fn who_vlan(&self, ip: Ipv4Addr) -> Option<(String, u16)> {
        let st = guard(&self.0.st);
        let key = st.by_ip.get(&ip)?;
        let id = &st.subs.get(key)?.id;
        st.active
            .get(id)
            .filter(|a| a.address == Some(ip))
            .map(|a| (a.name.clone(), a.vlan.unwrap_or(0)))
    }

    fn who_at(&self, ip: Ipv4Addr, at: u64) -> Option<String> {
        let st = guard(&self.0.st);
        st.history
            .iter()
            .rev()
            .find(|h| {
                h.address == Some(ip)
                    && h.event == "down"
                    && h.at >= at
                    && h.at.saturating_sub(h.uptime_secs) <= at
            })
            .map(|h| h.name.clone())
            .or_else(|| {
                let up = st.subs.values().find(|s| s.ip == ip && s.up_at <= at)?;
                Some(up.user.clone())
            })
    }
}

/// The RADIUS CoA/Disconnect owner (RFC 5176) of the IPoE sessions.
pub(crate) struct Owner(pub Arc<Core>);

impl SessionOwner for Owner {
    fn name(&self) -> &str {
        "ipoe"
    }

    fn handle(&self, req: &CoaRequest) -> CoaOutcome {
        let sel = &req.selector;
        let empty = sel.user_name.is_none()
            && sel.framed_ip.is_none()
            && sel.calling_station_id.is_none()
            && sel.nas_port_id.is_none()
            && sel.acct_session_id.is_none();
        if empty {
            return CoaOutcome::NotMine;
        }
        let hits: Vec<String> = {
            let st = guard(&self.0.st);
            let caller = sel
                .calling_station_id
                .as_deref()
                .map(|c| c.replace('-', ":"));
            let matches = |a: &ActiveSession| {
                sel.user_name.as_deref().is_none_or(|u| a.name == u)
                    && sel.framed_ip.is_none_or(|ip| a.address == Some(ip))
                    && caller
                        .as_deref()
                        .is_none_or(|c| a.caller_id.eq_ignore_ascii_case(c))
                    && sel
                        .nas_port_id
                        .as_deref()
                        .is_none_or(|n| a.interface == n || a.circuit_id.as_deref() == Some(n))
                    && sel
                        .acct_session_id
                        .as_deref()
                        .is_none_or(|s| st.by_acct.get(s) == Some(&a.id))
            };
            // By address or Acct-Session-Id from the indexes (G4.3hb's
            // PPPoE fix: no pass over every session per CoA).
            let indexed: Option<Option<&String>> =
                match (sel.framed_ip, sel.acct_session_id.as_deref()) {
                    (Some(ip), _) => Some(
                        st.by_ip
                            .get(&ip)
                            .and_then(|k| st.subs.get(k))
                            .map(|s| &s.id),
                    ),
                    (None, Some(a)) => Some(st.by_acct.get(a)),
                    (None, None) => None,
                };
            match indexed {
                Some(id) => id
                    .and_then(|id| st.active.get(id))
                    .filter(|a| matches(a))
                    .map(|a| a.id.clone())
                    .into_iter()
                    .collect(),
                None => st
                    .active
                    .values()
                    .filter(|a| matches(a))
                    .map(|a| a.id.clone())
                    .collect(),
            }
        };
        if hits.is_empty() {
            return CoaOutcome::NotMine;
        }
        match req.kind {
            CoaKind::Disconnect => {
                self.0.revoke(
                    &hits,
                    (
                        "radius-disconnect",
                        "o RADIUS mandou desconectar (Disconnect-Request): o CPE pede DHCP de novo",
                        cause::ADMIN_RESET,
                    ),
                    "disconnected by RADIUS",
                );
                CoaOutcome::Ack
            }
            CoaKind::Coa => {
                let rate = req
                    .changes
                    .iter()
                    .find(|a| a.name == "Mikrotik-Rate-Limit")
                    .map(|a| a.value.clone());
                if req.changes.iter().any(|a| a.name == "Framed-IP-Address") {
                    // A new address: the client gets it on its next DISCOVER.
                    self.0.revoke(
                        &hits,
                        (
                            "radius-new-address",
                            "o RADIUS deu outro endereço (CoA): o CPE pede DHCP de novo e o recebe",
                            cause::ADMIN_RESET,
                        ),
                        "new address from RADIUS",
                    );
                    return CoaOutcome::Ack;
                }
                let change = framed::route_change(&req.changes);
                if rate.is_none() && change.is_none() {
                    return if req.authorize_only {
                        CoaOutcome::Ack
                    } else {
                        CoaOutcome::Nak(401)
                    };
                }
                // RFC 5176 §2.3: all or nothing.
                if rate
                    .as_deref()
                    .is_some_and(|r| r.parse::<RateLimit>().is_err())
                {
                    return CoaOutcome::Nak(407);
                }
                let mut st = guard(&self.0.st);
                if let Some(c) = &change {
                    for id in &hits {
                        let ip = st.active.get(id).and_then(|a| a.address);
                        if let Err(why) = framed::check_change(&st.framed, &st.forbidden, id, ip, c)
                        {
                            log::info!("ipoe: CoA de rotas recusado: {why}");
                            return CoaOutcome::Nak(407);
                        }
                    }
                    for id in &hits {
                        change_routes(&mut st, id, c);
                    }
                }
                let Some(rate) = rate else {
                    return CoaOutcome::Ack;
                };
                for id in &hits {
                    let Some(k) = st.by_id.get(id).cloned() else {
                        continue;
                    };
                    let Some(s) = st.subs.get_mut(&k) else {
                        continue;
                    };
                    s.rate = Some(rate.clone());
                    let op = s.slot.map(|slot| {
                        let (up, down) = rates(Some(&rate));
                        XdpOp::Upsert {
                            slot,
                            interface: s.interface.clone(),
                            client_mac: s.mac,
                            ip: s.ip,
                            up,
                            down,
                            shape: s.shape,
                        }
                    });
                    if let Some(op) = op {
                        st.ops.push(op);
                    }
                    if let Some(a) = st.active.get_mut(id) {
                        a.rate_limit = Some(rate.clone());
                    }
                }
                CoaOutcome::Ack
            }
        }
    }
}

/// G4.3cd: a CoA's routes for session `id` (under the lock, checked
/// already): the new blocks first, then the old ones of the families the
/// CoA names go.
fn change_routes(st: &mut State, id: &str, c: &framed::RouteChange) {
    let Some(k) = st.by_id.get(id).cloned() else {
        return;
    };
    let Some(s) = st.subs.get(&k) else {
        return;
    };
    let (slot, ip, user) = (s.slot, s.ip, s.user.clone());
    let (old, kept): (Vec<_>, Vec<_>) = s.routes.iter().copied().partition(|(r, _)| c.replaces(r));
    let stays = |o: &(FramedRoute, RouteOrigin)| c.routes.iter().any(|n| n.0.dst == o.0.dst);
    let fresh: Vec<_> = c
        .routes
        .iter()
        .copied()
        .filter(|n| !old.iter().any(|o| o.0.dst == n.0.dst))
        .collect();
    let holder = Holder {
        session: id.to_owned(),
        user: user.clone(),
        origin: RouteOrigin::FramedRoute,
        lane: 0,
        service: "ipoe",
    };
    let adm = framed::admit(
        &st.framed,
        &st.forbidden,
        &fresh,
        &holder,
        Some(ip),
        Some(NO_V6),
    );
    let gone: Vec<_> = old.iter().copied().filter(|o| !stays(o)).collect();
    let mut now_routes = kept;
    now_routes.extend(old.iter().copied().filter(|o| stays(o)));
    now_routes.extend(adm.routes.iter().copied());
    for (r, add) in adm
        .routes
        .iter()
        .map(|x| (x.0, true))
        .chain(gone.iter().map(|x| (x.0, false)))
    {
        if let Some(slot) = slot {
            st.ops.push(XdpOp::Route {
                dst: r.dst,
                slot,
                add,
            });
        }
        if let IpNet::V4(dst) = r.dst {
            st.kroutes.push(KernelRoute { dst, via: ip, add });
        }
    }
    framed::release_all(&st.framed, &gone, id);
    let rows = framed::rows(&now_routes);
    if let Some(s) = st.subs.get_mut(&k) {
        s.routes = now_routes;
    }
    if let Some(a) = st.active.get_mut(id) {
        a.routes = rows.clone();
        a.refused_routes = adm.refused.clone();
    }
    let text = if rows.is_empty() {
        "nenhuma".to_owned()
    } else {
        rows.iter()
            .map(|r| r.route.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };
    st.logs.push((
        false,
        format!("IPoE: {user}: rotas trocadas por CoA: {text}"),
    ));
    for why in adm.refused {
        st.logs
            .push((true, format!("IPoE: {user}: rota recusada (CoA): {why}")));
    }
}

/// G4.3cd: the routes of a session in the Accounting-Request (RFC 2866
/// §5.13).
fn route_attributes(routes: &[(FramedRoute, RouteOrigin)]) -> Vec<Attribute> {
    routes
        .iter()
        .map(|(r, _)| {
            Attribute::new(
                if r.is_v6() {
                    "Framed-IPv6-Route"
                } else {
                    "Framed-Route"
                },
                r.to_string(),
            )
        })
        .collect()
}

/// The XDP entry of a session on a port with this index and MAC.
pub(crate) fn xdp_session(
    ifindex: u32,
    server_mac: [u8; 6],
    client_mac: [u8; 6],
    ip: Ipv4Addr,
    up: Rate,
    down: Rate,
    shape: Option<corerouter_hal::queue::Kind>,
) -> PppoeSession {
    PppoeSession {
        ifindex,
        sid: 0,
        client_mac,
        server_mac,
        ipv4: Some(ip),
        up,
        down,
        // Both ways through the kernel (its firewall sees them): the XDP
        // program polices and counts, then passes.
        fast_up: false,
        fast_down: false,
        ipoe: true,
        shape,
        ..PppoeSession::default()
    }
}

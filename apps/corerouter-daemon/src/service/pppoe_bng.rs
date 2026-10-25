//! The BNG of the `pppoe` service (G4.3d), without I/O: it takes frames,
//! the time and the running config, drives one `proto_pppoe::Server` per
//! `/interface pppoe-server server`, answers authentication (local
//! `/ppp secret`, or RADIUS through the G4.3j service) and addresses (its
//! own allocator over `/ip pool`), and returns frames to send and
//! [`Effect`]s for the driver (`pppoe.rs`): the XDP session map, the slow
//! path routes, hooks and address lists, which need the HAL or the
//! session lock. What the engine's commands read (`ppp.active.list`,
//! `ppp.why`, `ppp.history`) is kept in [`Shared`], behind its own lock.
//!
//! Driven by the service's thread only; RADIUS answers come back over a
//! channel ([`Bng::auth_inbox`]), so no callback ever touches the BNG.

// Only the Linux driver (`pppoe.rs`) runs the BNG.
#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use corerouter_engine::ppp::{PppBackend, expand_hook};
use corerouter_engine::radius::{AaaBackend, AcctSource, SessionOwner};
use corerouter_hal::pppoe::{PppoeCounters, PppoeOp, PppoeSession, Rate};
use corerouter_model::MacAddr;
use corerouter_model::cow::CowArc;
use corerouter_model::ip_pool::IpPools;
use corerouter_model::ppp::{
    ActiveSession, AddrOrPool, Effective, HistoryEntry, Ppp, PppAuth, PppHook, PppSecret,
    PppService, PppoeServer, ServiceStats, Stage, Why,
};
use corerouter_model::radius::{
    AaaService, AcctCounters, AcctRequest, AcctStatus, Attribute, AuthOutcome, AuthReply,
    AuthRequest as RadiusRequest, CoaKind, CoaOutcome, CoaRequest, Credentials,
};
use corerouter_proto_pppoe::auth::AUTH_STRING_LEN;
use corerouter_proto_pppoe::discovery::{self, Code};
use corerouter_proto_pppoe::layers::AuthSet;
use corerouter_proto_pppoe::lcp::AuthProto;
use corerouter_proto_pppoe::ppp::{self as wire_ppp, proto};
use corerouter_proto_pppoe::server::{
    AuthMethod, AuthVerdict, Authorization, DownReason, Event, Ipv4Assignment, Server,
    ServerConfig, ServerOutput, SessionRef, VlanFilter,
};
use corerouter_proto_pppoe::timer::Millis;
use corerouter_proto_pppoe::wire::Mac;
use corerouter_proto_radius::rate_limit::RateLimit;

/// Lines kept by `ppp.history`: a mass reconnect of 20 k subscribers is
/// 40 k lines (**estimado**: 50 k × ~250 B = 12 MB).
pub(crate) const HISTORY: usize = 50_000;
/// Users and MACs `ppp.why` remembers.
pub(crate) const WHY_KEYS: usize = 100_000;
/// Slots of the XDP session map (`dataplane-ebpf-common::pppoe::SESSIONS_MAX`).
pub(crate) const XDP_SLOTS: u32 = 1 << 17;
/// RADIUS answers older than this are dropped (the server gave up first).
const RADIUS_GRACE_MS: u64 = 35_000;

pub(crate) fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What the driver must do outside the BNG.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Effect {
    /// The XDP session map (G4.3c).
    Xdp(PppoeOp),
    /// The slow path's /32 route to `bng0` (no XDP).
    Route { ip: Ipv4Addr, add: bool },
    /// Engine commands (hooks, address lists), run under the session lock.
    Run {
        command: String,
        params: serde_json::Value,
    },
    /// A dynamic firewall address-list entry for a subscriber's address.
    AddressList {
        list: String,
        ip: Ipv4Addr,
        add: bool,
        comment: String,
    },
    /// A line for the router's log (`ppp` topic), Portuguese.
    Log { error: bool, text: String },
}

/// The stages in order, for [`Track::attempts`].
const STAGES: [Stage; 6] = [
    Stage::Padi,
    Stage::Padr,
    Stage::Lcp,
    Stage::Auth,
    Stage::Ncp,
    Stage::Up,
];

/// Per-stage attempts of one user or MAC (`ppp.why`). Small: there is one
/// per user and one per MAC (the last failure or end only, boxed; a
/// subscriber that is up is in the active table).
#[derive(Debug, Clone, Default)]
struct Track {
    attempts: [u32; 6],
    last_stage: Option<Stage>,
    last: Option<Box<HistoryEntry>>,
}

fn stage_index(s: Stage) -> usize {
    STAGES.iter().position(|x| *x == s).unwrap_or(0)
}

/// What the engine's commands and the RADIUS service read and ask.
#[derive(Default)]
pub(crate) struct Shared {
    pub active: BTreeMap<String, ActiveSession>,
    pub history: VecDeque<HistoryEntry>,
    why: HashMap<String, Track>,
    pub stats: ServiceStats,
    /// `ppp.active.remove` and Disconnect-Requests, for the next round.
    pub terminate: Vec<String>,
    /// CoA rate changes: session id, RouterOS rate-limit text.
    pub rates: Vec<(String, String)>,
    /// Acct-Session-Id → session id.
    by_acct: HashMap<String, String>,
}

impl Shared {
    fn track(&mut self, key: &str) -> Option<&mut Track> {
        if !self.why.contains_key(key) && self.why.len() >= WHY_KEYS {
            // Full: forget the lot rather than grow (a flood of MACs).
            self.why.clear();
        }
        Some(self.why.entry(key.to_owned()).or_default())
    }

    fn reach(&mut self, keys: &[&str], stage: Stage) {
        for k in keys {
            if let Some(t) = self.track(k) {
                if let Some(n) = t.attempts.get_mut(stage_index(stage)) {
                    *n = n.saturating_add(1);
                }
                t.last_stage = Some(stage);
            }
        }
    }

    fn record(&mut self, keys: &[&str], h: HistoryEntry) {
        for k in keys {
            if let Some(t) = self.track(k) {
                if let Some(st) = h.stage {
                    t.last_stage = Some(st);
                }
                if h.event != "up" {
                    t.last = Some(Box::new(h.clone()));
                }
            }
        }
        if self.history.len() >= HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(h);
    }
}

/// The [`PppBackend`] the engine gets: reads [`Shared`] only.
pub(crate) struct Backend(pub Arc<Mutex<Shared>>);

impl PppBackend for Backend {
    fn active(&self) -> Vec<ActiveSession> {
        guard(&self.0).active.values().cloned().collect()
    }

    fn terminate(&self, ids: &[String]) -> usize {
        let mut sh = guard(&self.0);
        let found: Vec<String> = ids
            .iter()
            .filter(|i| sh.active.contains_key(*i))
            .cloned()
            .collect();
        let n = found.len();
        sh.terminate.extend(found);
        n
    }

    fn history(&self) -> Vec<HistoryEntry> {
        guard(&self.0).history.iter().cloned().collect()
    }

    fn why(&self, name: Option<&str>, mac: Option<MacAddr>) -> Why {
        let sh = guard(&self.0);
        let key = name
            .map(str::to_owned)
            .or_else(|| mac.map(|m| m.to_string()))
            .unwrap_or_default();
        let active = sh
            .active
            .values()
            .find(|a| {
                name.is_some_and(|n| a.name == n)
                    || mac.is_some_and(|m| a.caller_id == m.to_string())
            })
            .map(|a| a.id.clone());
        let mut t = sh.why.get(&key).cloned().unwrap_or_default();
        // Before authentication the user is not known: the discovery
        // stages of a user are those of the MAC it last came from.
        if name.is_some()
            && let Some(m) = t.last.as_ref().map(|l| l.caller_id.clone())
            && let Some(by_mac) = sh.why.get(&m)
        {
            for st in [Stage::Padi, Stage::Padr, Stage::Lcp] {
                let i = stage_index(st);
                if let (Some(n), Some(slot)) = (by_mac.attempts.get(i), t.attempts.get_mut(i)) {
                    *slot = *n;
                }
            }
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
        let sh = guard(&self.0);
        let mut st = sh.stats.clone();
        st.sessions = sh.active.len() as u64;
        st
    }

    fn who(&self, ip: Ipv4Addr) -> Option<String> {
        guard(&self.0)
            .active
            .values()
            .find(|a| a.address == Some(ip))
            .map(|a| a.name.clone())
    }

    fn who_at(&self, ip: Ipv4Addr, at: u64) -> Option<String> {
        let sh = guard(&self.0);
        // A session that ended after `at` and began before it.
        sh.history
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
                sh.active
                    .values()
                    .find(|a| a.address == Some(ip))
                    .map(|a| a.name.clone())
            })
    }
}

/// The RADIUS CoA/Disconnect owner (RFC 5176): matches the selector
/// against the active sessions and queues the change for the BNG.
pub(crate) struct Owner(pub Arc<Mutex<Shared>>);

impl SessionOwner for Owner {
    fn name(&self) -> &str {
        "ppp"
    }

    fn handle(&self, req: &CoaRequest) -> CoaOutcome {
        let mut sh = guard(&self.0);
        let sel = &req.selector;
        let hits: Vec<String> = sh
            .active
            .values()
            .filter(|a| {
                sel.user_name.as_deref().is_none_or(|u| a.name == u)
                    && sel.framed_ip.is_none_or(|ip| a.address == Some(ip))
                    && sel
                        .calling_station_id
                        .as_deref()
                        .is_none_or(|c| a.caller_id.eq_ignore_ascii_case(&c.replace('-', ":")))
                    && sel
                        .nas_port_id
                        .as_deref()
                        .is_none_or(|n| a.interface == n || a.circuit_id.as_deref() == Some(n))
            })
            .filter(|a| {
                sel.acct_session_id
                    .as_deref()
                    .is_none_or(|s| sh.by_acct.get(s) == Some(&a.id))
            })
            .map(|a| a.id.clone())
            .collect();
        let empty = sel.user_name.is_none()
            && sel.framed_ip.is_none()
            && sel.calling_station_id.is_none()
            && sel.nas_port_id.is_none()
            && sel.acct_session_id.is_none();
        if hits.is_empty() || empty {
            return CoaOutcome::NotMine;
        }
        match req.kind {
            CoaKind::Disconnect => sh.terminate.extend(hits),
            CoaKind::Coa => {
                let rate = req
                    .changes
                    .iter()
                    .find(|a| a.name == "Mikrotik-Rate-Limit")
                    .map(|a| a.value.clone());
                let new_ip = req.changes.iter().any(|a| a.name == "Framed-IP-Address");
                if new_ip {
                    // PPP cannot move an open IPCP to a new address: the
                    // subscriber reconnects and gets it.
                    sh.terminate.extend(hits);
                } else if let Some(r) = rate {
                    if r.parse::<RateLimit>().is_err() {
                        return CoaOutcome::Nak(407); // Invalid Attribute Value
                    }
                    for h in hits {
                        sh.rates.push((h, r.clone()));
                    }
                } else if !req.authorize_only {
                    return CoaOutcome::Nak(401); // Unsupported Attribute
                }
            }
        }
        CoaOutcome::Ack
    }
}

/// Counters of one session for the RADIUS interims.
struct Counters {
    shared: Arc<Mutex<Shared>>,
    id: String,
}

impl AcctSource for Counters {
    fn counters(&self) -> Option<AcctCounters> {
        let sh = guard(&self.shared);
        let a = sh.active.get(&self.id)?;
        Some(acct_counters(a))
    }
}

fn acct_counters(a: &ActiveSession) -> AcctCounters {
    AcctCounters {
        // RFC 2866 §5.3/§5.4: from the NAS port's view: input = from the user.
        input_octets: a.rx_bytes,
        output_octets: a.tx_bytes,
        input_packets: a.rx_packets,
        output_packets: a.tx_packets,
        session_time: u32::try_from(a.uptime_secs).unwrap_or(u32::MAX),
    }
}

/// An `/ip pool` allocator of the PPP service. The pool's addresses the
/// DHCP server hands out are not seen here: a pool belongs to one of them.
#[derive(Default)]
struct Pools {
    used: HashSet<u32>,
    cursor: HashMap<String, u32>,
}

impl Pools {
    fn take(&mut self, pools: &IpPools, name: &str) -> Option<(Ipv4Addr, String)> {
        for p in pools.chain(name) {
            let size = p.size();
            if size == 0 {
                continue;
            }
            let start = self.cursor.get(&p.name).copied().unwrap_or(0);
            let mut i = 0u64;
            while i < size {
                let at = (u64::from(start) + i) % size;
                if let Some(ip) = nth(p, at)
                    && !self.used.contains(&u32::from(ip))
                {
                    self.used.insert(u32::from(ip));
                    self.cursor
                        .insert(p.name.clone(), u32::try_from((at + 1) % size).unwrap_or(0));
                    return Some((ip, p.name.clone()));
                }
                i += 1;
            }
        }
        None
    }

    fn hold(&mut self, ip: Ipv4Addr) -> bool {
        self.used.insert(u32::from(ip))
    }

    fn give_back(&mut self, ip: Ipv4Addr) {
        self.used.remove(&u32::from(ip));
    }
}

fn nth(p: &corerouter_model::ip_pool::IpPool, mut at: u64) -> Option<Ipv4Addr> {
    for r in &p.ranges {
        if at < r.len() {
            let base = u64::from(u32::from(r.start));
            return u32::try_from(base + at).ok().map(Ipv4Addr::from);
        }
        at -= r.len();
    }
    None
}

/// A token bucket of new sessions per second (`new_session_rate`).
#[derive(Debug, Clone, Copy)]
struct Bucket {
    rate: u32,
    tokens: f64,
    at: Millis,
}

impl Bucket {
    fn new(rate: u32, now: Millis) -> Self {
        Self {
            rate,
            tokens: f64::from(rate.max(1)),
            at: now,
        }
    }

    fn allow(&mut self, now: Millis) -> bool {
        if self.rate == 0 {
            return true;
        }
        let dt = now.saturating_sub(self.at) as f64 / 1000.0;
        self.at = now;
        let cap = f64::from(self.rate);
        self.tokens = (self.tokens + dt * cap).min(cap);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// A port the driver opened for a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PortInfo {
    pub ifindex: u32,
    pub mac: [u8; 6],
}

struct Slot {
    cfg: PppoeServer,
    port: PortInfo,
    server: Server,
    bucket: Bucket,
}

/// A session the BNG knows (from PADR to its Down).
struct Sub {
    slot: usize,
    sref: SessionRef,
    user: String,
    mac: Mac,
    stage: Stage,
    effective: Effective,
    radius: bool,
    /// The address and the pool it came from (`None`: fixed).
    ip: Option<Ipv4Addr>,
    pool: Option<String>,
    rate: Option<String>,
    acct_id: String,
    interim: Option<u32>,
    xdp: Option<u32>,
    up_at: Option<Millis>,
    limit_in: u64,
    limit_out: u64,
    session_timeout: Option<u32>,
    reply_message: Option<String>,
    /// Why it was ended here, when the reason is ours (idle, limit).
    cause: Option<(u32, &'static str)>,
    last_bytes: (u64, u64),
    idle_since: Millis,
    descriptor_vlan: Option<u16>,
    circuit_id: Option<String>,
    remote_id: Option<String>,
    mtu: u16,
}

/// What the hot paths look up in [`Bng::subs`] without walking it
/// (G4.3g: a walk per PADI, per login and per slow-path packet made a
/// session cost grow with the sessions up: 19 → 181 µs from 0 to 60 000).
#[derive(Default)]
struct SubIndex {
    /// Sessions up, by address: the slow path's downstream lookup.
    by_ip: HashMap<Ipv4Addr, (usize, u16)>,
    /// Sessions up per login: `only-one`.
    users_up: HashMap<String, u32>,
    /// Sessions between authentication and Up, per (slot, MAC): the PADI's
    /// `new_session_rate`.
    pending: HashMap<(usize, [u8; 6]), u32>,
}

impl SubIndex {
    fn add(&mut self, key: (usize, u16), sub: &Sub) {
        if sub.up_at.is_some() {
            *self.users_up.entry(sub.user.clone()).or_default() += 1;
            if let Some(ip) = sub.ip {
                self.by_ip.insert(ip, key);
            }
        } else {
            *self.pending.entry((sub.slot, sub.mac.0)).or_default() += 1;
        }
    }

    fn remove(&mut self, key: (usize, u16), sub: &Sub) {
        fn dec<K: std::hash::Hash + Eq>(m: &mut HashMap<K, u32>, k: &K) {
            if let Some(n) = m.get_mut(k) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    m.remove(k);
                }
            }
        }
        if sub.up_at.is_some() {
            dec(&mut self.users_up, &sub.user);
            if let Some(ip) = sub.ip
                && self.by_ip.get(&ip) == Some(&key)
            {
                self.by_ip.remove(&ip);
            }
        } else {
            dec(&mut self.pending, &(sub.slot, sub.mac.0));
        }
    }
}

/// An answer for the server, queued while its events are handled.
enum Reply {
    Auth(AuthVerdict),
    Address(Option<Ipv4Assignment>),
    Terminate,
}

/// A RADIUS answer on its way back to the BNG thread.
pub(crate) struct AuthDone {
    slot: usize,
    sref: SessionRef,
    asked: Millis,
    reply: AuthReply,
}

/// The running config the BNG follows.
#[derive(Clone, Default)]
pub(crate) struct Snapshot {
    pub ppp: Ppp,
    pub pools: IpPools,
    /// The daemon's RADIUS service, if any.
    pub aaa: Option<Arc<dyn AaaBackend>>,
    /// Unix time of `now` = 0 (the history's clock).
    pub unix_base: u64,
}

pub(crate) struct Bng {
    slots: Vec<Slot>,
    subs: HashMap<(usize, u16), Sub>,
    /// Kept with `subs` (every insert, remove and Up goes through it).
    index: SubIndex,
    /// `/ppp secret` by name, for the list it was built from
    /// (`Ppp::secret` walks the list: 100 000 secrets made a login cost
    /// ~100 µs more for the last ones, G4.3g).
    secrets: (CowArc<Vec<PppSecret>>, HashMap<String, usize>),
    pools: Pools,
    xdp_free: Vec<u32>,
    xdp_next: u32,
    pub shared: Arc<Mutex<Shared>>,
    pub effects: Vec<Effect>,
    /// Frames to send: (ifindex, bytes).
    pub frames: Vec<(u32, Vec<u8>)>,
    /// Slow path: subscribers' IPv4 packets for the stack.
    pub upstream: Vec<Vec<u8>>,
    replies: VecDeque<(usize, SessionRef, Reply)>,
    auth_tx: Sender<AuthDone>,
    auth_rx: Receiver<AuthDone>,
    pending_auth: usize,
    cfg: Snapshot,
    seq: u64,
    seed: [u8; 32],
    out: ServerOutput,
    /// The data plane takes the traffic (else the slow path does).
    pub xdp: bool,
    /// PADIs held back by `new_session_rate`.
    padr_throttled: u64,
}

/// One discovery or session frame's code and source, read before the
/// server sees it (`ppp.why` counts, the session-rate limit).
fn peek(frame: &[u8]) -> Option<(Code, Mac)> {
    let d = discovery::parse(frame).ok()?;
    Some((d.code, d.src))
}

fn mac_text(m: Mac) -> String {
    MacAddr(m.0).to_string()
}

fn auth_set(list: &[PppAuth]) -> AuthSet {
    let protos: Vec<AuthProto> = list
        .iter()
        .map(|a| match a {
            PppAuth::Mschap2 => AuthProto::MsChapV2,
            PppAuth::Mschap1 => AuthProto::MsChapV1,
            PppAuth::Chap => AuthProto::ChapMd5,
            PppAuth::Pap => AuthProto::Pap,
        })
        .collect();
    AuthSet::new(&protos)
}

/// `proto-pppoe`'s configuration for one server entry.
pub(crate) fn server_config(
    v: &PppoeServer,
    mac: [u8; 6],
    local: Option<Ipv4Addr>,
) -> ServerConfig {
    let mut c = ServerConfig {
        ac_mac: Mac(mac),
        ac_name: b"CoreRouter".to_vec(),
        service_names: if v.service_name.is_empty() {
            Vec::new()
        } else {
            vec![v.service_name.as_bytes().to_vec()]
        },
        one_session_per_host: v.one_session_per_host,
        auth: auth_set(&v.authentication),
        max_mru: v.max_mru,
        max_mtu: v.max_mtu,
        require_cookie: v.ac_cookie,
        padi_limit: v.padi_limit,
        mac_padi_limit: v.mac_padi_limit,
        local_ipv4: local,
        ..ServerConfig::default()
    };
    // RouterOS keepalive-timeout: echoes from timeout/2, gone after timeout.
    match v.keepalive_timeout {
        Some(t) => {
            c.keepalive_interval_ms = u64::from(t) * 500;
            c.keepalive_misses = 2;
        }
        None => c.keepalive_interval_ms = 0,
    }
    let mut tiers: Vec<(u32, u32)> = vec![(0, v.pado_delay)];
    tiers.extend(
        v.pado_delay_by_load
            .iter()
            .map(|t| (t.sessions, v.pado_delay.saturating_add(t.delay_ms))),
    );
    tiers.retain(|t| t.1 > 0);
    c.pado_delay = tiers;
    c.vlans = if v.pppoe_over_vlan_range.is_empty() {
        VlanFilter::Untagged
    } else {
        let mut r: Vec<std::ops::RangeInclusive<u16>> = v
            .pppoe_over_vlan_range
            .iter()
            .map(|x| x.first..=x.last)
            .collect();
        if v.accept_untagged {
            r.push(0..=0);
        }
        VlanFilter::Ranges(r)
    };
    c
}

/// The VLAN ids a server listens on (for the driver's sockets).
pub(crate) fn vlan_ids(v: &PppoeServer) -> Vec<u16> {
    v.pppoe_over_vlan_range
        .iter()
        .flat_map(|r| r.first..=r.last)
        .collect()
}

/// What a session ending means, for the log, the history and RADIUS.
pub(crate) fn explain(r: DownReason) -> (&'static str, &'static str, Stage, u32) {
    // (reason, hint in Portuguese, stage, RFC 2866 §5.10 Acct-Terminate-Cause)
    match r {
        DownReason::PeerPadt => (
            "peer-padt",
            "O CPE encerrou a sessão (PADT). Normal ao desligar; se repete em loop, veja o CPE.",
            Stage::Up,
            1,
        ),
        DownReason::PeerTerminate => (
            "peer-terminate",
            "O CPE pediu o fim do enlace (LCP Terminate-Request).",
            Stage::Up,
            1,
        ),
        DownReason::Admin => (
            "admin",
            "Desconectado pelo operador (ppp.active.remove) ou por um Disconnect/CoA do RADIUS.",
            Stage::Up,
            6,
        ),
        DownReason::AuthFailed => (
            "auth-failed",
            "Usuário ou senha recusados: confira o secret (ppp.secret.list) ou a mensagem do RADIUS.",
            Stage::Auth,
            17,
        ),
        DownReason::AuthTimeout => (
            "auth-timeout",
            "A autenticação não respondeu a tempo: RADIUS lento ou fora (radius.monitor), ou o CPE não mandou as credenciais.",
            Stage::Auth,
            17,
        ),
        DownReason::LcpFailed => (
            "lcp-failed",
            "O LCP não fechou: MRU/MTU ou método de autenticação que o CPE não aceita (authentication do servidor).",
            Stage::Lcp,
            8,
        ),
        DownReason::NcpFailed => (
            "ncp-failed",
            "Sem endereço IP: pool cheio ou sem remote_address no perfil (ip.pool.print).",
            Stage::Ncp,
            8,
        ),
        DownReason::Keepalive => (
            "keepalive",
            "O CPE parou de responder ao LCP echo: queda de energia, do enlace ou CPE travado.",
            Stage::Up,
            2,
        ),
        DownReason::SetupTimeout => (
            "setup-timeout",
            "A sessão não subiu em 60 s depois do PADS.",
            Stage::Lcp,
            8,
        ),
        DownReason::SessionTimeout => (
            "session-timeout",
            "Fim do tempo de sessão (session_timeout do perfil ou Session-Timeout do RADIUS).",
            Stage::Up,
            5,
        ),
        DownReason::Replaced => (
            "replaced",
            "Nova sessão do mesmo MAC (one-session-per-host): o CPE reiniciou sem mandar PADT.",
            Stage::Up,
            10,
        ),
    }
}

impl Bng {
    pub(crate) fn new(seed: [u8; 32]) -> Self {
        let (auth_tx, auth_rx) = channel();
        Self {
            slots: Vec::new(),
            subs: HashMap::new(),
            index: SubIndex::default(),
            secrets: (CowArc::default(), HashMap::new()),
            pools: Pools::default(),
            xdp_free: Vec::new(),
            xdp_next: 0,
            shared: Arc::new(Mutex::new(Shared::default())),
            effects: Vec::new(),
            frames: Vec::new(),
            upstream: Vec::new(),
            replies: VecDeque::new(),
            auth_tx,
            auth_rx,
            pending_auth: 0,
            cfg: Snapshot::default(),
            seq: 0,
            seed,
            out: ServerOutput::new(),
            xdp: false,
            padr_throttled: 0,
        }
    }

    fn log(&mut self, error: bool, text: String) {
        self.effects.push(Effect::Log { error, text });
    }

    /// Servers the config wants, with what the driver must open.
    pub(crate) fn wanted(cfg: &Ppp) -> Vec<PppoeServer> {
        cfg.pppoe_servers
            .iter()
            .filter(|v| !v.disabled)
            .cloned()
            .collect()
    }

    /// Follow the config: `ports` has the port of each wanted server the
    /// driver opened (by server name). A server whose port or restart
    /// fields changed starts over (its sessions end); other changes reach
    /// new sessions.
    pub(crate) fn configure(
        &mut self,
        now: Millis,
        snap: Snapshot,
        ports: &HashMap<String, PortInfo>,
    ) {
        let wanted = Self::wanted(&snap.ppp);
        if !CowArc::ptr_eq(&self.secrets.0, &snap.ppp.secrets) {
            let mut by_name = HashMap::with_capacity(snap.ppp.secrets.len());
            for (k, sec) in snap.ppp.secrets.iter().enumerate() {
                // The first of a name wins, as `Ppp::secret` (the engine
                // refuses duplicates anyway).
                by_name.entry(sec.name.clone()).or_insert(k);
            }
            self.secrets = (snap.ppp.secrets.clone(), by_name);
        }
        self.cfg = snap;
        // Servers gone or restarted: end their sessions.
        let mut keep: Vec<bool> = Vec::with_capacity(self.slots.len());
        for s in &self.slots {
            let same = wanted.iter().find(|w| w.id == s.cfg.id).is_some_and(|w| {
                w.interface == s.cfg.interface
                    && w.service_name == s.cfg.service_name
                    && w.pppoe_over_vlan_range == s.cfg.pppoe_over_vlan_range
                    && w.accept_untagged == s.cfg.accept_untagged
                    && ports.get(&w.name) == Some(&s.port)
            });
            keep.push(same);
        }
        let mut i = self.slots.len();
        while i > 0 {
            i -= 1;
            if keep.get(i).copied().unwrap_or(false) {
                continue;
            }
            self.drop_slot(now, i);
        }
        for w in wanted {
            let Some(port) = ports.get(&w.name).copied() else {
                continue;
            };
            let local = match self
                .cfg
                .ppp
                .profile(&w.default_profile)
                .and_then(|p| p.local_address)
            {
                Some(AddrOrPool::Address(ip)) => Some(ip),
                _ => None,
            };
            let sc = server_config(&w, port.mac, local);
            match self.slots.iter_mut().find(|s| s.cfg.id == w.id) {
                Some(s) => {
                    s.server.reconfigure(sc);
                    if s.bucket.rate != w.new_session_rate {
                        s.bucket = Bucket::new(w.new_session_rate, now);
                    }
                    s.cfg = w;
                }
                None => {
                    let mut seed = self.seed;
                    if let Some(b) = seed.first_mut() {
                        *b ^= (self.slots.len() as u8).wrapping_add(1);
                    }
                    let name = w.name.clone();
                    let interface = w.interface.to_string();
                    self.slots.push(Slot {
                        bucket: Bucket::new(w.new_session_rate, now),
                        server: Server::new(sc, seed, now),
                        port,
                        cfg: w,
                    });
                    self.log(
                        false,
                        format!("PPPoE: servidor {name} atendendo em {interface}"),
                    );
                }
            }
        }
    }

    /// Remove slot `i`, ending its sessions without frames (the port is
    /// gone or restarts: the CPEs reconnect after their keepalive or our
    /// PADT to their next frame).
    fn drop_slot(&mut self, now: Millis, i: usize) {
        let keys: Vec<(usize, u16)> = self.subs.keys().filter(|k| k.0 == i).copied().collect();
        for k in keys {
            if let Some(sub) = self.take_sub(k) {
                self.ended(now, sub, DownReason::Admin, true);
            }
        }
        if i < self.slots.len() {
            let s = self.slots.remove(i);
            self.log(false, format!("PPPoE: servidor {} parado", s.cfg.name));
        }
        // Slots after `i` moved down one.
        let moved: Vec<((usize, u16), Sub)> = self
            .subs
            .drain()
            .map(|((slot, sid), mut sub)| {
                let slot = if slot > i { slot - 1 } else { slot };
                sub.slot = slot;
                ((slot, sid), sub)
            })
            .collect();
        self.subs.extend(moved);
        // The slots were renumbered: index again (a server removed, rare).
        self.index = SubIndex::default();
        for (k, sub) in &self.subs {
            self.index.add(*k, sub);
        }
    }

    /// Remove a session, keeping the index.
    fn take_sub(&mut self, key: (usize, u16)) -> Option<Sub> {
        let sub = self.subs.remove(&key)?;
        self.index.remove(key, &sub);
        Some(sub)
    }

    /// The earliest time [`Bng::timers`] has work.
    pub(crate) fn next_deadline(&self) -> Option<Millis> {
        self.slots
            .iter()
            .filter_map(|s| s.server.next_deadline())
            .min()
    }

    pub(crate) fn waiting_radius(&self) -> bool {
        self.pending_auth > 0
    }

    /// A frame from the port `ifindex`.
    pub(crate) fn frame(&mut self, now: Millis, ifindex: u32, frame: &[u8]) {
        let Some(i) = self.slots.iter().position(|s| s.port.ifindex == ifindex) else {
            return;
        };
        if let Some((code, src)) = peek(frame) {
            let key = mac_text(src);
            let sessions = self.subs.len();
            let Some(slot) = self.slots.get_mut(i) else {
                return;
            };
            let full =
                slot.cfg.max_sessions > 0 && slot.server.active() >= slot.cfg.max_sessions as usize;
            match code {
                Code::Padi => {
                    guard(&self.shared).stats.padi += 1;
                    guard(&self.shared).reach(&[&key], Stage::Padi);
                    if full {
                        return;
                    }
                    // `new_session_rate` is spent at the PADI: no PADO, the
                    // CPE asks again (RFC 2516 §5.1: PADI retransmitted with
                    // back-off). At the PADR it would be worse: the CPE
                    // repeats the PADR with an AC-Cookie that expires.
                    let setting_up = self.index.pending.contains_key(&(i, src.0));
                    if !setting_up && !slot.bucket.allow(now) {
                        self.padr_throttled += 1;
                        return;
                    }
                }
                Code::Padr => {
                    guard(&self.shared).stats.padr += 1;
                    if full {
                        return;
                    }
                    guard(&self.shared).reach(&[&key], Stage::Padr);
                }
                Code::Padt => guard(&self.shared).stats.padt_rx += 1,
                _ => {}
            }
            let _ = sessions;
        } else if let Ok(f) = wire_ppp::parse_session(frame)
            && matches!(f.protocol, proto::IPV4)
        {
            // Slow path upstream: the XDP would have taken it.
            self.data_up(i, &f);
            return;
        }
        self.run(now, i, |srv, out| {
            srv.handle_frame(now, ifindex, frame, out)
        });
    }

    /// Upstream IPv4 of a session without XDP: checked (the session and its
    /// address, the anti-spoofing of G4.3c) and counted; the driver sends
    /// the packet into the stack.
    fn data_up(&mut self, slot: usize, f: &wire_ppp::SessionFrame<'_>) {
        let Some(sub) = self.subs.get(&(slot, f.session_id)) else {
            return;
        };
        if sub.mac != f.link.src || sub.up_at.is_none() {
            return;
        }
        let src = f.info.get(12..16).map(|b| {
            Ipv4Addr::new(
                b.first().copied().unwrap_or(0),
                b.get(1).copied().unwrap_or(0),
                b.get(2).copied().unwrap_or(0),
                b.get(3).copied().unwrap_or(0),
            )
        });
        if src.is_none() || src != sub.ip {
            return;
        }
        let id = session_id(slot, &self.slots, f.session_id);
        let len = f.info.len() as u64;
        if let Some(a) = guard(&self.shared).active.get_mut(&id) {
            a.rx_bytes += len;
            a.rx_packets += 1;
        }
        self.upstream.push(f.info.to_vec());
    }

    /// Downstream IPv4 to a subscriber (slow path): encapsulated for its
    /// session, or dropped when nobody has the address.
    pub(crate) fn data_down(&mut self, packet: &[u8]) {
        let Some(dst) = packet.get(16..20) else {
            return;
        };
        let dst = Ipv4Addr::new(
            dst.first().copied().unwrap_or(0),
            dst.get(1).copied().unwrap_or(0),
            dst.get(2).copied().unwrap_or(0),
            dst.get(3).copied().unwrap_or(0),
        );
        let Some(((slot, sid), sub)) = self
            .index
            .by_ip
            .get(&dst)
            .and_then(|k| self.subs.get_key_value(k))
        else {
            return;
        };
        let Some(port) = self.slots.get(*slot).map(|s| s.port) else {
            return;
        };
        if packet.len() > usize::from(sub.mtu.max(576)) {
            return;
        }
        let mut f = Vec::with_capacity(packet.len() + 26);
        f.extend_from_slice(&sub.mac.0);
        f.extend_from_slice(&port.mac);
        if let Some(v) = sub.descriptor_vlan {
            f.extend_from_slice(&0x8100u16.to_be_bytes());
            f.extend_from_slice(&(v & 0x0FFF).to_be_bytes());
        }
        f.extend_from_slice(&0x8864u16.to_be_bytes());
        let len = u16::try_from(packet.len() + 2).unwrap_or(u16::MAX);
        f.extend_from_slice(&[0x11, 0x00]);
        f.extend_from_slice(&sid.to_be_bytes());
        f.extend_from_slice(&len.to_be_bytes());
        f.extend_from_slice(&proto::IPV4.to_be_bytes());
        f.extend_from_slice(packet);
        let id = session_id(*slot, &self.slots, *sid);
        if let Some(a) = guard(&self.shared).active.get_mut(&id) {
            a.tx_bytes += packet.len() as u64;
            a.tx_packets += 1;
        }
        self.frames.push((port.ifindex, f));
    }

    /// Call server `i`, handle what it says, then the answers that
    /// produced, until nothing is left.
    fn run(&mut self, now: Millis, i: usize, f: impl FnOnce(&mut Server, &mut ServerOutput)) {
        let mut out = std::mem::take(&mut self.out);
        if let Some(slot) = self.slots.get_mut(i) {
            f(&mut slot.server, &mut out);
        }
        self.absorb(now, i, &mut out);
        while let Some((j, sref, reply)) = self.replies.pop_front() {
            if let Some(slot) = self.slots.get_mut(j) {
                let srv = &mut slot.server;
                match reply {
                    Reply::Auth(v) => {
                        srv.auth_reply(now, sref, v, &mut out);
                    }
                    Reply::Address(a) => {
                        srv.address_reply(now, sref, a, &mut out);
                    }
                    Reply::Terminate => {
                        srv.terminate(now, sref, &mut out);
                    }
                }
            }
            self.absorb(now, j, &mut out);
        }
        self.out = out;
    }

    fn absorb(&mut self, now: Millis, i: usize, out: &mut ServerOutput) {
        for (ifindex, f) in out.frames() {
            if let Ok(d) = discovery::parse(f) {
                let mut sh = guard(&self.shared);
                match d.code {
                    Code::Pado => sh.stats.pado += 1,
                    Code::Pads if d.session_id != 0 => {
                        sh.stats.pads += 1;
                        sh.reach(&[&mac_text(d.dst)], Stage::Lcp);
                    }
                    Code::Padt => sh.stats.padt_tx += 1,
                    _ => {}
                }
            }
            self.frames.push((ifindex, f.to_vec()));
        }
        let events: Vec<Event> = std::mem::take(&mut out.events);
        out.clear();
        for ev in events {
            self.event(now, i, ev);
        }
    }

    fn event(&mut self, now: Millis, i: usize, ev: Event) {
        match ev {
            Event::Authenticate { session, request } => {
                self.authenticate(now, i, session, &request)
            }
            Event::NeedAddress { session } => {
                let a = self.subs.get_mut(&(i, session.sid)).and_then(|sub| {
                    let pool =
                        sub.pool
                            .clone()
                            .or_else(|| match &sub.effective.remote_address {
                                Some(AddrOrPool::Pool(p)) => Some(p.clone()),
                                _ => None,
                            })?;
                    let (ip, from) = self.pools.take(&self.cfg.pools, &pool)?;
                    sub.ip = Some(ip);
                    sub.pool = Some(from);
                    Some(assignment(ip, &sub.effective.dns_server))
                });
                self.replies.push_back((i, session, Reply::Address(a)));
            }
            Event::Up {
                session,
                descriptor,
            } => self.up(now, i, session, &descriptor),
            Event::Changed {
                session,
                descriptor,
            } => {
                if let Some(sub) = self.subs.get(&(i, session.sid))
                    && let Some(idx) = sub.xdp
                {
                    let s = xdp_session(&descriptor, sub.rate.as_deref());
                    self.effects.push(Effect::Xdp(PppoeOp::Upsert(idx, s)));
                }
            }
            Event::Down {
                session,
                reason,
                was_up,
                ..
            } => {
                if let Some(sub) = self.take_sub((i, session.sid)) {
                    self.ended(now, sub, reason, was_up);
                }
            }
        }
    }

    fn reject(&mut self, i: usize, sref: SessionRef, why: &str) {
        guard(&self.shared).stats.auth_reject += 1;
        if let Some(sub) = self.subs.get_mut(&(i, sref.sid)) {
            sub.reply_message = Some(why.to_owned());
        }
        self.replies.push_back((
            i,
            sref,
            Reply::Auth(AuthVerdict::Reject {
                message: why.as_bytes().into(),
            }),
        ));
    }

    fn authenticate(
        &mut self,
        now: Millis,
        i: usize,
        sref: SessionRef,
        req: &corerouter_proto_pppoe::server::AuthRequest,
    ) {
        let user = String::from_utf8_lossy(&req.username).into_owned();
        let mac = req.client_mac;
        let Some(slot) = self.slots.get(i) else {
            return;
        };
        let default_profile = slot.cfg.default_profile.clone();
        let vlan = (req.vlans.outer != 0).then_some(req.vlans.outer);
        let fresh = Sub {
            slot: i,
            sref,
            user: user.clone(),
            mac,
            stage: Stage::Auth,
            effective: self
                .cfg
                .ppp
                .effective(None, &default_profile, &default_profile),
            radius: false,
            ip: None,
            pool: None,
            rate: None,
            acct_id: String::new(),
            interim: None,
            xdp: None,
            up_at: None,
            limit_in: 0,
            limit_out: 0,
            session_timeout: None,
            reply_message: None,
            cause: None,
            last_bytes: (0, 0),
            idle_since: now,
            descriptor_vlan: vlan,
            circuit_id: req
                .circuit_id
                .as_ref()
                .map(|c| String::from_utf8_lossy(c).into_owned()),
            remote_id: req
                .remote_id
                .as_ref()
                .map(|c| String::from_utf8_lossy(c).into_owned()),
            mtu: 1480,
        };
        self.index.add((i, sref.sid), &fresh);
        if let Some(old) = self.subs.insert((i, sref.sid), fresh) {
            // Authenticated again (LCP renegotiated): the old entry's
            // place in the index goes.
            self.index.remove((i, sref.sid), &old);
        }
        guard(&self.shared).reach(&[&user, &mac_text(mac)], Stage::Auth);
        let secret = self
            .secrets
            .1
            .get(&user)
            .and_then(|&k| self.secrets.0.get(k))
            .cloned();
        match secret {
            Some(sec) if sec.disabled => self.reject(i, sref, "secret disabled"),
            Some(sec) => self.local(i, sref, req, &sec, &default_profile),
            None => match self.cfg.aaa.clone().filter(|_| self.cfg.ppp.aaa.use_radius) {
                Some(aaa) => self.ask_radius(now, i, sref, req, &user, &aaa),
                None => self.reject(i, sref, "no such user"),
            },
        }
    }

    fn local(
        &mut self,
        i: usize,
        sref: SessionRef,
        req: &corerouter_proto_pppoe::server::AuthRequest,
        sec: &corerouter_model::ppp::PppSecret,
        default_profile: &str,
    ) {
        if !sec.service.allows(PppService::Pppoe) {
            return self.reject(i, sref, "service not allowed for this secret");
        }
        if sec.caller_id.is_some_and(|m| m.0 != req.client_mac.0) {
            return self.reject(i, sref, "caller-id mismatch");
        }
        let e = self
            .cfg
            .ppp
            .effective(Some(sec), &sec.profile, default_profile);
        if e.only_one && self.index.users_up.contains_key(&sec.name) {
            return self.reject(i, sref, "only-one: the user is already connected");
        }
        let Some(mschap2) = req.verify_local(&sec.password) else {
            return self.reject(i, sref, "wrong password");
        };
        let (limit_in, limit_out) = (sec.limit_bytes_in, sec.limit_bytes_out);
        let fixed = match &e.remote_address {
            Some(AddrOrPool::Address(ip)) => Some(*ip),
            _ => None,
        };
        let pool = match &e.remote_address {
            Some(AddrOrPool::Pool(p)) => Some(p.clone()),
            _ => None,
        };
        let rate = e.rate_limit.clone();
        let timeout = e.session_timeout;
        if let Some(sub) = self.subs.get_mut(&(i, sref.sid)) {
            sub.effective = e;
            sub.limit_in = limit_in;
            sub.limit_out = limit_out;
        }
        self.accept(i, sref, mschap2, fixed, pool, rate, timeout, false, None);
    }

    #[allow(clippy::too_many_arguments)]
    fn accept(
        &mut self,
        i: usize,
        sref: SessionRef,
        mschap2: Option<[u8; AUTH_STRING_LEN]>,
        fixed: Option<Ipv4Addr>,
        pool: Option<String>,
        rate: Option<String>,
        timeout: Option<u32>,
        radius: bool,
        interim: Option<u32>,
    ) {
        let Some(sub) = self.subs.get_mut(&(i, sref.sid)) else {
            return;
        };
        // A fixed address held by another session: refuse rather than
        // hand one address to two subscribers.
        let ipv4 = match fixed {
            Some(ip) if !self.pools.hold(ip) => {
                sub.reply_message = Some(format!("address {ip} is in use"));
                self.replies.push_back((
                    i,
                    sref,
                    Reply::Auth(AuthVerdict::Reject {
                        message: format!("address {ip} is in use").into_bytes().into(),
                    }),
                ));
                return;
            }
            Some(ip) => {
                sub.ip = Some(ip);
                Some(assignment(ip, &sub.effective.dns_server))
            }
            None => match pool
                .as_deref()
                .and_then(|p| self.pools.take(&self.cfg.pools, p))
            {
                Some((ip, from)) => {
                    sub.ip = Some(ip);
                    sub.pool = Some(from);
                    Some(assignment(ip, &sub.effective.dns_server))
                }
                // Asked again at IPCP (`NeedAddress`); none then = NCP fails.
                None => {
                    sub.pool = pool;
                    None
                }
            },
        };
        sub.rate = rate.clone();
        sub.radius = radius;
        sub.interim = interim;
        sub.session_timeout = timeout;
        guard(&self.shared).stats.auth_accept += 1;
        let auth = Authorization {
            mschap2_success: mschap2,
            message: Box::default(),
            ipv4,
            rate_limit: rate.as_deref().and_then(|r| r.parse::<RateLimit>().ok()),
            session_timeout: timeout,
        };
        self.replies
            .push_back((i, sref, Reply::Auth(AuthVerdict::Accept(auth))));
    }

    fn ask_radius(
        &mut self,
        now: Millis,
        i: usize,
        sref: SessionRef,
        req: &corerouter_proto_pppoe::server::AuthRequest,
        user: &str,
        aaa: &Arc<dyn AaaBackend>,
    ) {
        let credentials = match &req.method {
            AuthMethod::Pap { password } => Credentials::Pap {
                password: String::from_utf8_lossy(password).into_owned(),
            },
            AuthMethod::Chap {
                id,
                challenge,
                response,
            } => Credentials::Chap {
                id: *id,
                challenge: challenge.to_vec(),
                response: response.to_vec(),
            },
            AuthMethod::MsChapV2 {
                id,
                challenge,
                response,
            } => Credentials::MsChapV2 {
                ident: *id,
                challenge: challenge.to_vec(),
                peer_challenge: response.peer_challenge.to_vec(),
                nt_response: response.nt_response.to_vec(),
            },
            AuthMethod::MsChapV1 { .. } => {
                return self.reject(
                    i,
                    sref,
                    "MS-CHAPv1 is not sent to RADIUS: use mschap2, chap or pap",
                );
            }
        };
        let Some(slot) = self.slots.get(i) else {
            return;
        };
        let circuit = req
            .circuit_id
            .as_ref()
            .map(|c| String::from_utf8_lossy(c).into_owned());
        let nas_port_id = match circuit {
            Some(c) if self.cfg.ppp.aaa.use_circuit_id_in_nas_port_id => c,
            _ => slot.cfg.interface.to_string(),
        };
        let r = RadiusRequest {
            service: AaaService::Ppp,
            user: user.to_owned(),
            credentials,
            nas_port_id: Some(nas_port_id),
            nas_port: Some(u32::from(sref.sid)),
            calling_station_id: Some(mac_text(req.client_mac)),
            called_station_id: (!slot.cfg.service_name.is_empty())
                .then(|| slot.cfg.service_name.clone()),
            // RFC 2865 §5.6 Framed (2), §5.7 PPP (1), §5.41 Virtual (5):
            // what a PPPoE NAS sends (RFC 4679 §4 for the DSL ones).
            attributes: vec![
                Attribute::new("Service-Type", "2"),
                Attribute::new("Framed-Protocol", "1"),
                Attribute::new("NAS-Port-Type", "5"),
            ],
        };
        let tx = self.auth_tx.clone();
        self.pending_auth += 1;
        aaa.authenticate(
            r,
            Box::new(move |reply| {
                // The BNG's thread reads it; nothing else happens here.
                let _ = tx.send(AuthDone {
                    slot: i,
                    sref,
                    asked: now,
                    reply,
                });
            }),
        );
    }

    /// RADIUS answers that arrived.
    pub(crate) fn radius(&mut self, now: Millis) {
        while let Ok(done) = self.auth_rx.try_recv() {
            self.pending_auth = self.pending_auth.saturating_sub(1);
            let key = (done.slot, done.sref.sid);
            if self.subs.get(&key).is_none_or(|s| s.sref != done.sref)
                || now.saturating_sub(done.asked) > RADIUS_GRACE_MS
            {
                continue;
            }
            let (i, sref) = (done.slot, done.sref);
            let attr = |name: &str| {
                done.reply
                    .attributes
                    .iter()
                    .find(|a| a.name == name)
                    .map(|a| a.value.clone())
            };
            let message = attr("Reply-Message").or_else(|| done.reply.message.clone());
            if let Some(sub) = self.subs.get_mut(&key) {
                sub.reply_message = message.clone();
            }
            match done.reply.outcome {
                AuthOutcome::Accept => {
                    let profile = attr("Mikrotik-Group");
                    let default_profile = self
                        .slots
                        .get(i)
                        .map(|s| s.cfg.default_profile.clone())
                        .unwrap_or_default();
                    let e = self.cfg.ppp.effective(
                        None,
                        profile.as_deref().unwrap_or(&default_profile),
                        &default_profile,
                    );
                    let fixed = attr("Framed-IP-Address").and_then(|v| v.parse::<Ipv4Addr>().ok());
                    let pool = attr("Framed-Pool").or(match &e.remote_address {
                        Some(AddrOrPool::Pool(p)) => Some(p.clone()),
                        _ => None,
                    });
                    let fixed = fixed.or(match &e.remote_address {
                        Some(AddrOrPool::Address(ip)) if pool.is_none() => Some(*ip),
                        _ => None,
                    });
                    let rate = attr("Mikrotik-Rate-Limit")
                        .filter(|r| r.parse::<RateLimit>().is_ok())
                        .or(e.rate_limit.clone());
                    let timeout = attr("Session-Timeout")
                        .and_then(|v| v.parse::<u32>().ok())
                        .or(e.session_timeout);
                    let interim = attr("Acct-Interim-Interval").and_then(|v| v.parse::<u32>().ok());
                    let mschap2 = attr("MS-CHAP2-Success").and_then(|v| success_string(&v));
                    let list = attr("Mikrotik-Address-List");
                    if let Some(sub) = self.subs.get_mut(&key) {
                        sub.effective = e;
                        if list.is_some() {
                            sub.effective.address_list = list;
                        }
                    }
                    self.accept(i, sref, mschap2, fixed, pool, rate, timeout, true, interim);
                }
                AuthOutcome::Reject | AuthOutcome::Challenge => {
                    let m = message.unwrap_or_else(|| "rejected by RADIUS".into());
                    self.reject(i, sref, &m);
                }
                AuthOutcome::Timeout | AuthOutcome::Error => {
                    let m = message.unwrap_or_else(|| "RADIUS did not answer".into());
                    self.reject(i, sref, &format!("RADIUS: {m}"));
                }
            }
            self.run(now, i, |_, _| {});
        }
    }

    fn up(
        &mut self,
        now: Millis,
        i: usize,
        sref: SessionRef,
        d: &corerouter_proto_pppoe::descriptor::SessionDescriptor,
    ) {
        let id = session_id(i, &self.slots, sref.sid);
        let Some(slot) = self.slots.get(i) else {
            return;
        };
        let server = slot.cfg.name.clone();
        let interface = slot.cfg.interface.to_string();
        let unix = self.cfg.unix_base + now / 1000;
        self.seq += 1;
        let acct_id = format!("{:08X}{:04X}", unix as u32, self.seq as u16);
        let xdp = if self.xdp { self.slot_index() } else { None };
        let Some(sub) = self.subs.get_mut(&(i, sref.sid)) else {
            return;
        };
        self.index.remove((i, sref.sid), sub);
        sub.up_at = Some(now);
        sub.stage = Stage::Up;
        sub.idle_since = now;
        sub.acct_id = acct_id.clone();
        sub.mtu = d.mtu;
        sub.xdp = xdp;
        if sub.ip.is_none() {
            sub.ip = d.ipv4;
        }
        self.index.add((i, sref.sid), sub);
        let ip = sub.ip;
        let user = sub.user.clone();
        let mac = mac_text(sub.mac);
        match xdp {
            Some(idx) => self.effects.push(Effect::Xdp(PppoeOp::Upsert(
                idx,
                xdp_session(d, sub.rate.as_deref()),
            ))),
            None => {
                if let Some(ip) = ip {
                    self.effects.push(Effect::Route { ip, add: true });
                }
            }
        }
        let a = ActiveSession {
            id: id.clone(),
            name: user.clone(),
            service: "pppoe".into(),
            caller_id: mac.clone(),
            address: ip,
            session_id: sref.sid,
            server: server.clone(),
            interface: interface.clone(),
            vlan: sub.descriptor_vlan,
            circuit_id: sub.circuit_id.clone(),
            remote_id: sub.remote_id.clone(),
            rate_limit: sub.rate.clone(),
            profile: sub.effective.profile.clone(),
            encoding: d
                .auth
                .map(|a| match a {
                    AuthProto::Pap => "pap",
                    AuthProto::ChapMd5 => "chap",
                    AuthProto::MsChapV1 => "mschap1",
                    AuthProto::MsChapV2 => "mschap2",
                })
                .unwrap_or("none")
                .into(),
            radius: sub.radius,
            mtu: d.mtu,
            limit_bytes_in: (sub.limit_in > 0).then_some(sub.limit_in),
            limit_bytes_out: (sub.limit_out > 0).then_some(sub.limit_out),
            ..ActiveSession::default()
        };
        let radius_acct = sub.radius || self.cfg.ppp.aaa.use_radius;
        let interim = sub.interim;
        let list = sub.effective.address_list.clone();
        let hooks = sub.effective.on_up.clone();
        {
            let mut sh = guard(&self.shared);
            sh.active.insert(id.clone(), a);
            sh.by_acct.insert(acct_id.clone(), id.clone());
            sh.reach(&[&user, &mac], Stage::Up);
            sh.record(
                &[&user, &mac],
                HistoryEntry {
                    at: unix,
                    name: user.clone(),
                    caller_id: mac.clone(),
                    server: server.clone(),
                    event: "up".into(),
                    stage: Some(Stage::Up),
                    address: ip,
                    ..HistoryEntry::default()
                },
            );
        }
        if radius_acct
            && self.cfg.ppp.aaa.accounting
            && let Some(aaa) = &self.cfg.aaa
        {
            let src: Arc<dyn AcctSource> = Arc::new(Counters {
                shared: self.shared.clone(),
                id: id.clone(),
            });
            let req = AcctRequest {
                service: AaaService::Ppp,
                status: AcctStatus::Start,
                session_id: acct_id,
                user: user.clone(),
                counters: None,
                terminate_cause: None,
                interim_secs: interim,
                attributes: acct_attributes(ip, &mac, &interface),
            };
            if let Err(e) = aaa.account(req, Some(src)) {
                self.log(
                    true,
                    format!("PPP: Accounting-Start de {user} não enviado: {e}"),
                );
            }
        }
        if let (Some(l), Some(ip)) = (list, ip) {
            self.effects.push(Effect::AddressList {
                list: l,
                ip,
                add: true,
                comment: format!("ppp {user}"),
            });
        }
        self.hooks(&hooks, &user, ip, &mac, &interface);
        self.log(
            false,
            format!(
                "PPP: {user} conectado ({mac}, {}, {server})",
                ip.map_or_else(|| "sem IPv4".into(), |i| i.to_string())
            ),
        );
    }

    fn hooks(
        &mut self,
        hooks: &[PppHook],
        user: &str,
        ip: Option<Ipv4Addr>,
        mac: &str,
        interface: &str,
    ) {
        let local = match self
            .cfg
            .ppp
            .profile(corerouter_model::ppp::DEFAULT_PROFILE)
            .and_then(|p| p.local_address)
        {
            Some(AddrOrPool::Address(ip)) => ip.to_string(),
            _ => String::new(),
        };
        let vars = [
            ("$user", user.to_owned()),
            (
                "$remote-address",
                ip.map(|i| i.to_string()).unwrap_or_default(),
            ),
            ("$local-address", local),
            ("$caller-id", mac.to_owned()),
            ("$interface", interface.to_owned()),
            ("$service", "pppoe".to_owned()),
        ];
        for h in hooks {
            self.effects.push(Effect::Run {
                command: h.command.clone(),
                params: expand_hook(&h.params, &vars),
            });
        }
    }

    fn slot_index(&mut self) -> Option<u32> {
        if let Some(i) = self.xdp_free.pop() {
            return Some(i);
        }
        (self.xdp_next < XDP_SLOTS).then(|| {
            self.xdp_next += 1;
            self.xdp_next - 1
        })
    }

    /// A session is gone: undo everything [`Bng::up`] did.
    fn ended(&mut self, now: Millis, sub: Sub, reason: DownReason, was_up: bool) {
        let (mut key, mut hint, stage, mut cause) = explain(reason);
        if let Some((c, k)) = sub.cause {
            cause = c;
            key = k;
            hint = match k {
                "idle-timeout" => "Sem tráfego pelo idle_timeout do perfil.",
                "limit-bytes" => "Atingiu limit_bytes_in/out do secret.",
                _ => hint,
            };
        }
        let id = session_id(sub.slot, &self.slots, sub.sref.sid);
        if let Some(idx) = sub.xdp {
            self.effects.push(Effect::Xdp(PppoeOp::Remove(idx)));
            self.xdp_free.push(idx);
        } else if let (Some(ip), true) = (sub.ip, was_up) {
            self.effects.push(Effect::Route { ip, add: false });
        }
        if let Some(ip) = sub.ip {
            self.pools.give_back(ip);
        }
        let mac = mac_text(sub.mac);
        let server = self
            .slots
            .get(sub.slot)
            .map(|s| s.cfg.name.clone())
            .unwrap_or_default();
        let interface = self
            .slots
            .get(sub.slot)
            .map(|s| s.cfg.interface.to_string())
            .unwrap_or_default();
        let unix = self.cfg.unix_base + now / 1000;
        let gone = {
            let mut sh = guard(&self.shared);
            let gone = sh.active.remove(&id);
            sh.by_acct.remove(&sub.acct_id);
            gone
        };
        let uptime = sub.up_at.map_or(0, |t| now.saturating_sub(t) / 1000);
        if was_up {
            if (sub.radius || self.cfg.ppp.aaa.use_radius)
                && self.cfg.ppp.aaa.accounting
                && let Some(aaa) = &self.cfg.aaa
            {
                let mut counters = gone.as_ref().map(acct_counters).unwrap_or_default();
                counters.session_time = u32::try_from(uptime).unwrap_or(u32::MAX);
                let req = AcctRequest {
                    service: AaaService::Ppp,
                    status: AcctStatus::Stop,
                    session_id: sub.acct_id.clone(),
                    user: sub.user.clone(),
                    counters: Some(counters),
                    terminate_cause: Some(cause),
                    interim_secs: None,
                    attributes: acct_attributes(sub.ip, &mac, &interface),
                };
                if let Err(e) = aaa.account(req, None) {
                    self.log(
                        true,
                        format!("PPP: Accounting-Stop de {} não enviado: {e}", sub.user),
                    );
                }
            }
            if let (Some(l), Some(ip)) = (&sub.effective.address_list, sub.ip) {
                self.effects.push(Effect::AddressList {
                    list: l.clone(),
                    ip,
                    add: false,
                    comment: String::new(),
                });
            }
            let hooks = sub.effective.on_down.clone();
            self.hooks(&hooks, &sub.user, sub.ip, &mac, &interface);
        }
        let failed_stage = if was_up {
            Stage::Up
        } else if stage == Stage::Up {
            sub.stage
        } else {
            stage
        };
        let h = HistoryEntry {
            at: unix,
            name: sub.user.clone(),
            caller_id: mac.clone(),
            server,
            event: if was_up {
                "down".into()
            } else {
                "failed".into()
            },
            stage: Some(failed_stage),
            reason: key.into(),
            hint: hint.into(),
            reply_message: sub.reply_message.clone(),
            address: sub.ip,
            uptime_secs: uptime,
            rx_bytes: gone.as_ref().map_or(0, |a| a.rx_bytes),
            tx_bytes: gone.as_ref().map_or(0, |a| a.tx_bytes),
        };
        guard(&self.shared).record(&[&sub.user, &mac], h);
        if was_up {
            self.log(
                false,
                format!("PPP: {} desconectado ({key}, {uptime} s): {hint}", sub.user),
            );
        } else {
            let msg = sub
                .reply_message
                .as_deref()
                .map(|m| format!(" — {m}"))
                .unwrap_or_default();
            self.log(
                false,
                format!(
                    "PPP: login de {} ({mac}) falhou em {}{msg}: {hint}",
                    sub.user,
                    failed_stage.as_str()
                ),
            );
        }
    }

    /// The servers' timers.
    pub(crate) fn timers(&mut self, now: Millis) {
        for i in 0..self.slots.len() {
            let due = self
                .slots
                .get(i)
                .and_then(|s| s.server.next_deadline())
                .is_some_and(|d| d <= now);
            if due {
                self.run(now, i, |srv, out| srv.handle_timers(now, out));
            }
        }
    }

    /// Once a second: counters (from XDP when it carries the traffic),
    /// uptime, idle and byte limits, and what the commands and the RADIUS
    /// service asked for.
    pub(crate) fn tick(&mut self, now: Millis, xdp: &[(u32, PppoeCounters)]) {
        let by_idx: HashMap<u32, PppoeCounters> = xdp.iter().copied().collect();
        // PADIs the servers' limiters held back count as throttled too.
        let limited: u64 = self
            .slots
            .iter()
            .map(|s| s.server.stats().padi_limited)
            .sum();
        guard(&self.shared).stats.throttled = self.padr_throttled + limited;
        let mut ending: Vec<(usize, SessionRef, (u32, &'static str))> = Vec::new();
        {
            let mut sh = guard(&self.shared);
            for ((slot, sid), sub) in self.subs.iter_mut() {
                let Some(up) = sub.up_at else { continue };
                let id = session_id(*slot, &self.slots, *sid);
                let Some(a) = sh.active.get_mut(&id) else {
                    continue;
                };
                if let Some(c) = sub.xdp.and_then(|i| by_idx.get(&i)) {
                    a.rx_bytes = c.up_bytes;
                    a.rx_packets = c.up_packets;
                    a.tx_bytes = c.down_bytes;
                    a.tx_packets = c.down_packets;
                }
                a.uptime_secs = now.saturating_sub(up) / 1000;
                let bytes = (a.rx_bytes, a.tx_bytes);
                if bytes != sub.last_bytes {
                    sub.last_bytes = bytes;
                    sub.idle_since = now;
                }
                if sub.cause.is_some() {
                    continue;
                }
                if let Some(idle) = sub.effective.idle_timeout
                    && now.saturating_sub(sub.idle_since) >= u64::from(idle) * 1000
                {
                    sub.cause = Some((4, "idle-timeout"));
                } else if (sub.limit_in > 0 && a.rx_bytes >= sub.limit_in)
                    || (sub.limit_out > 0 && a.tx_bytes >= sub.limit_out)
                {
                    sub.cause = Some((10, "limit-bytes"));
                }
                if let Some(c) = sub.cause {
                    ending.push((*slot, sub.sref, c));
                }
            }
        }
        for (i, sref, _) in ending {
            self.replies.push_back((i, sref, Reply::Terminate));
            self.run(now, i, |_, _| {});
        }
        self.requests(now);
    }

    /// `ppp.active.remove`, Disconnect and CoA rate changes.
    pub(crate) fn requests(&mut self, now: Millis) {
        let (ids, rates) = {
            let mut sh = guard(&self.shared);
            (
                std::mem::take(&mut sh.terminate),
                std::mem::take(&mut sh.rates),
            )
        };
        for id in ids {
            if let Some((i, sref)) = self.find(&id) {
                self.replies.push_back((i, sref, Reply::Terminate));
                self.run(now, i, |_, _| {});
            }
        }
        for (id, rate) in rates {
            let Some((i, sref)) = self.find(&id) else {
                continue;
            };
            let Some(srv) = self.slots.get(i).map(|s| &s.server) else {
                continue;
            };
            let Some(d) = srv.session(sref.sid) else {
                continue;
            };
            if let Some(sub) = self.subs.get_mut(&(i, sref.sid)) {
                sub.rate = Some(rate.clone());
                if let Some(idx) = sub.xdp {
                    self.effects.push(Effect::Xdp(PppoeOp::Upsert(
                        idx,
                        xdp_session(&d, Some(&rate)),
                    )));
                }
                let user = sub.user.clone();
                if let Some(a) = guard(&self.shared).active.get_mut(&id) {
                    a.rate_limit = Some(rate.clone());
                }
                self.log(
                    false,
                    format!("PPP: {user} com rate-limit novo {rate} (CoA)"),
                );
            }
        }
    }

    fn find(&self, id: &str) -> Option<(usize, SessionRef)> {
        self.subs
            .iter()
            .find(|((slot, sid), _)| session_id(*slot, &self.slots, *sid) == id)
            .map(|(_, s)| (s.slot, s.sref))
    }

    /// End every session (service stopping): Terminate and PADT to each.
    pub(crate) fn shutdown(&mut self, now: Millis) {
        let all: Vec<(usize, SessionRef)> = self.subs.values().map(|s| (s.slot, s.sref)).collect();
        for (i, sref) in all {
            self.replies.push_back((i, sref, Reply::Terminate));
            self.run(now, i, |_, _| {});
        }
    }

    /// XDP slots of the sessions up, for the counters.
    pub(crate) fn xdp_slots(&self) -> Vec<u32> {
        self.subs.values().filter_map(|s| s.xdp).collect()
    }

    /// Debug builds and tests: the servers' indexes agree.
    #[cfg(test)]
    pub(crate) fn check(&self) -> Result<(), String> {
        for s in &self.slots {
            s.server.check_invariants()?;
        }
        let ips: Vec<u32> = self
            .subs
            .values()
            .filter_map(|s| s.ip)
            .map(u32::from)
            .collect();
        let unique: HashSet<u32> = ips.iter().copied().collect();
        if unique.len() != ips.len() {
            return Err("an address is held by two sessions".into());
        }
        let mut again = SubIndex::default();
        for (k, sub) in &self.subs {
            again.add(*k, sub);
        }
        if again.by_ip != self.index.by_ip
            || again.users_up != self.index.users_up
            || again.pending != self.index.pending
        {
            return Err("the session index disagrees with the sessions".into());
        }
        Ok(())
    }
}

fn session_id(slot: usize, slots: &[Slot], sid: u16) -> String {
    let server = slots.get(slot).map_or(0, |s| s.cfg.id.0);
    format!("*{server:X}-{sid}")
}

fn assignment(ip: Ipv4Addr, dns: &[Ipv4Addr]) -> Ipv4Assignment {
    Ipv4Assignment {
        address: ip,
        dns: [dns.first().copied(), dns.get(1).copied()],
        nbns: [None, None],
    }
}

fn acct_attributes(ip: Option<Ipv4Addr>, mac: &str, interface: &str) -> Vec<Attribute> {
    let mut v = vec![
        Attribute::new("Calling-Station-Id", mac),
        Attribute::new("NAS-Port-Id", interface),
        Attribute::new("Framed-Protocol", "1"),
    ];
    if let Some(ip) = ip {
        v.push(Attribute::new("Framed-IP-Address", ip.to_string()));
    }
    v
}

/// The `S=…` string of an MS-CHAP2-Success attribute (RFC 2548 §2.3.3:
/// Ident, then 42 octets), shown as text or as hex.
fn success_string(v: &str) -> Option<[u8; AUTH_STRING_LEN]> {
    let bytes: Vec<u8> = if let Some(at) = v.find("S=") {
        v.get(at..)?.as_bytes().to_vec()
    } else {
        let hex = v.strip_prefix("0x").unwrap_or(v);
        let raw: Vec<u8> = (0..hex.len() / 2)
            .filter_map(|i| {
                hex.get(i * 2..i * 2 + 2)
                    .and_then(|b| u8::from_str_radix(b, 16).ok())
            })
            .collect();
        raw.get(1..)?.to_vec()
    };
    bytes.get(..AUTH_STRING_LEN)?.try_into().ok()
}

fn rate_dir(r: &RateLimit, up: bool) -> Rate {
    let pick = |p: corerouter_proto_radius::rate_limit::Pair<u64>| if up { p.rx } else { p.tx };
    Rate {
        rate_bps: pick(r.rate),
        burst_bps: r.burst_rate.map_or(0, pick),
        threshold_bps: r.burst_threshold.map_or(0, pick),
        burst_secs: r.burst_time.map_or(0, |t| if up { t.rx } else { t.tx }),
    }
}

/// The XDP map entry of a session (G4.3c): downstream always in XDP
/// (the kernel path to the subscriber is G4.3ca), upstream through the
/// kernel so `forward` and the queues see it.
fn xdp_session(
    d: &corerouter_proto_pppoe::descriptor::SessionDescriptor,
    rate: Option<&str>,
) -> PppoeSession {
    let r = rate
        .and_then(|t| t.parse::<RateLimit>().ok())
        .or(d.rate_limit);
    PppoeSession {
        ifindex: d.ifindex,
        sid: d.sid,
        vlan: d.vlan,
        inner_vlan: d.inner_vlan,
        outer_tpid: d.outer_tpid,
        mtu: d.mtu,
        client_mac: d.client_mac.0,
        server_mac: d.server_mac.0,
        ipv4: d.ipv4,
        up: r.as_ref().map(|r| rate_dir(r, true)).unwrap_or_default(),
        down: r.as_ref().map(|r| rate_dir(r, false)).unwrap_or_default(),
        fast_up: false,
        fast_down: true,
    }
}

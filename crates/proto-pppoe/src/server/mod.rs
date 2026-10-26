//! The access concentrator: PPPoE Discovery (RFC 2516 §5) and, per
//! session, LCP → authentication → IPCP/IPv6CP (RFC 1661 §3.2 phases).
//!
//! Sans-IO: the caller feeds received frames ([`Server::handle_frame`]),
//! fires timers ([`Server::handle_timers`] at [`Server::next_deadline`]) and
//! answers the questions the server asks through [`Event`]s — verify these
//! credentials ([`Server::auth_reply`]), give this subscriber an address
//! ([`Server::address_reply`]). Everything to transmit comes back in an
//! [`Output`]. One `Server` is one SESSION_ID space (≤ 65 534 sessions,
//! RFC 2516 §4); the BNG service runs one per access port group.

pub mod ha;
mod services;
mod session;

use crate::auth::{self, AUTH_STRING_LEN, MsChapResponse};
use crate::discovery::{self, Code, DEFAULT_MRU, Discovery, DiscoveryWriter, tag};
use crate::eth::{self, ETHERTYPE_DISCOVERY, ETHERTYPE_SESSION, Vlans};
use crate::fsm::{FsmConfig, Scratch};
use crate::guard::{CookieJar, PadiLimiter, Rng};
use crate::layers::AuthSet;
use crate::output::Output;
use crate::ppp;
use crate::timer::{Entry, Millis, Wheel};
use crate::wire::Mac;
use corerouter_proto_radius::rate_limit::RateLimit;
use session::Session;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::net::Ipv4Addr;
use std::ops::RangeInclusive;

pub use crate::descriptor::{SessionDescriptor, SessionKey};
pub use services::{ServiceAction, ServiceRule, ServiceSlot, ServiceTable};

/// RFC 2516 §4: SESSION_ID 0xffff is reserved, 0 means "no session".
pub const MAX_SID: u16 = 0xfffe;

/// Which VLANs the server answers (RouterOS v7 `pppoe-over-vlan-range`;
/// G4.3l: Junos `stacked-vlan-ranges`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum VlanFilter {
    #[default]
    Any,
    Untagged,
    /// One tag in these ranges (0..=0 = untagged too).
    Ranges(Vec<RangeInclusive<u16>>),
    /// Two tags: the outer in `outer` with this TPID, the inner in `inner`
    /// (empty: any); `untagged` serves untagged frames too.
    Stacked {
        outer: Vec<RangeInclusive<u16>>,
        inner: Vec<RangeInclusive<u16>>,
        tpid: u16,
        untagged: bool,
    },
}

impl VlanFilter {
    pub fn allows(&self, v: Vlans) -> bool {
        match self {
            VlanFilter::Any => true,
            VlanFilter::Untagged => !v.is_tagged(),
            VlanFilter::Ranges(r) => v.inner == 0 && r.iter().any(|r| r.contains(&v.outer)),
            VlanFilter::Stacked {
                outer,
                inner,
                tpid,
                untagged,
            } => {
                if !v.is_tagged() {
                    return *untagged;
                }
                v.inner != 0
                    && v.outer_tpid == *tpid
                    && outer.iter().any(|r| r.contains(&v.outer))
                    && (inner.is_empty() || inner.iter().any(|r| r.contains(&v.inner)))
            }
        }
    }
}

/// Server settings. Defaults follow RouterOS v7 (`/interface pppoe-server
/// server` and `/ppp profile`) and accel-ppp where RouterOS has none.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Source MAC of everything we send (the access port's).
    pub ac_mac: Mac,
    /// AC-Name tag (RFC 2516 §5.2: MUST be in every PADO).
    pub ac_name: Vec<u8>,
    /// The Service-Name table (G4.3k): what each name a subscriber asks
    /// for gets. Default: every name served (RouterOS `service-name=""`).
    pub services: ServiceTable,
    /// Upper bound on sessions (RouterOS `max-sessions`; ≤ 65 534).
    pub max_sessions: u16,
    /// A new PADR from a MAC drops its old session (RouterOS
    /// `one-session-per-host`).
    pub one_session_per_host: bool,
    /// Authentication, in preference order (RouterOS default: mschap2,
    /// mschap1, chap, pap). Empty = none (open access).
    pub auth: AuthSet,
    /// MRU we offer (RouterOS `max-mru`, default 1480).
    pub max_mru: u16,
    /// Largest peer MRU we send to (RouterOS `max-mtu`, default 1480).
    pub max_mtu: u16,
    /// RFC 4638: largest PPP-Max-Payload we accept; `None` keeps 1492.
    pub max_payload: Option<u16>,
    /// LCP echo period (RouterOS `keepalive-timeout` 10 s = two misses of
    /// 5 s).
    pub keepalive_interval_ms: u64,
    pub keepalive_misses: u8,
    /// RFC 1661 §4.6 timers and counters.
    pub fsm: FsmConfig,
    /// AC-Cookie lifetime (accel-ppp `cookie-timeout`).
    pub cookie_timeout_ms: u64,
    /// PADR without a valid AC-Cookie is ignored (RFC 2516 §9).
    pub require_cookie: bool,
    /// PADIs answered per second overall (accel-ppp `padi-limit`); 0 = no limit.
    pub padi_limit: u32,
    /// PADIs answered per second per MAC, with this burst; 0 = no limit.
    pub mac_padi_limit: u32,
    pub mac_padi_burst: u32,
    /// accel-ppp `pado-delay`: `(sessions at least, delay ms)` tiers.
    pub pado_delay: Vec<(u32, u32)>,
    pub vlans: VlanFilter,
    /// Our IPCP address (RouterOS profile `local-address`); `None` =
    /// unnumbered.
    pub local_ipv4: Option<Ipv4Addr>,
    /// Run IPv6CP (interface ids; the prefixes come from the service, G4.3e).
    pub ipv6: bool,
    /// RFC 8064 / RFC 7217 secret: our IPv6CP identifier and the one we
    /// suggest to a subscriber are stable per (port, VLANs, MAC) and opaque
    /// (`nd::stable_iid`). `None` = random per session.
    pub ipv6_iid_key: Option<[u8; 32]>,
    /// How long an authentication or address answer may take (RADIUS
    /// timeouts × retries fit under it).
    pub answer_timeout_ms: u64,
    /// PADS to first network protocol up.
    pub setup_timeout_ms: u64,
    /// Delayed PADOs held at most.
    pub pado_queue: usize,
    /// Sessions per (port, VLAN stack); 0 = no limit (G4.3l: 1 is TR-101's
    /// 1:1 model, a line per VLAN).
    pub max_per_vlan: u32,
    /// `(lane, lanes)`: this server hands out only the SESSION_IDs with
    /// `sid % lanes == lane`. Several servers on one port (the service's
    /// workers, one per core) then share its SESSION_ID space without a
    /// lock (RFC 2516 §4: unique per port). `(0, 1)`: all of them.
    pub sid_lane: (u16, u16),
    /// G4.3h: the AC-Cookie key of a redundant pair. Both nodes accept
    /// each other's cookies (a PADR in flight at a switchover still
    /// lands): the key is shared and the cookie does not bind the port
    /// (its index differs between the two machines). `None`: a key of
    /// this server's own, bound to the port.
    pub cookie_secret: Option<[u8; 32]>,
}

impl ServerConfig {
    /// The SESSION_IDs this server may use, in order.
    fn sids(&self) -> impl Iterator<Item = u16> + use<> {
        let (lane, lanes) = (self.sid_lane.0, self.sid_lane.1.max(1));
        (1..=self.max_sessions).filter(move |s| s % lanes == lane % lanes)
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            ac_mac: Mac([0x02, 0, 0, 0, 0, 1]),
            ac_name: b"CoreRouter".to_vec(),
            services: ServiceTable::default(),
            max_sessions: MAX_SID,
            one_session_per_host: true,
            auth: AuthSet::routeros_default(),
            max_mru: 1480,
            max_mtu: 1480,
            max_payload: None,
            keepalive_interval_ms: 5000,
            keepalive_misses: 2,
            fsm: FsmConfig::default(),
            cookie_timeout_ms: 5000,
            require_cookie: true,
            padi_limit: 0,
            mac_padi_limit: 0,
            mac_padi_burst: 3,
            pado_delay: Vec::new(),
            vlans: VlanFilter::Any,
            local_ipv4: None,
            ipv6: false,
            ipv6_iid_key: None,
            answer_timeout_ms: 30_000,
            setup_timeout_ms: 60_000,
            pado_queue: 4096,
            max_per_vlan: 0,
            sid_lane: (0, 1),
            cookie_secret: None,
        }
    }
}

/// Names a session across asynchronous answers: a stale reference (the
/// session ended, the SID was reused) is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionRef {
    pub sid: u16,
    pub gen_: u32,
}

/// What the subscriber proved, for the caller to check (locally or over
/// RADIUS).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthMethod {
    /// RFC 1334: the password in clear (RADIUS User-Password).
    Pap { password: Box<[u8]> },
    /// RFC 1994 (RADIUS CHAP-Password = id ‖ response, CHAP-Challenge).
    Chap {
        id: u8,
        challenge: [u8; 16],
        response: [u8; 16],
    },
    /// RFC 2433 (RADIUS MS-CHAP-Challenge + MS-CHAP-Response).
    MsChapV1 {
        id: u8,
        challenge: [u8; 8],
        response: MsChapResponse,
    },
    /// RFC 2759 (RADIUS MS-CHAP-Challenge + MS-CHAP2-Response).
    MsChapV2 {
        id: u8,
        challenge: [u8; 16],
        response: MsChapResponse,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthRequest {
    pub username: Box<[u8]>,
    pub method: AuthMethod,
    pub client_mac: Mac,
    pub ifindex: u32,
    pub vlans: Vlans,
    pub circuit_id: Option<Box<[u8]>>,
    pub remote_id: Option<Box<[u8]>>,
    /// The Service-Name of the PADR (G4.3k: the profile is chosen by it).
    pub service: Box<[u8]>,
}

impl AuthRequest {
    /// Checks the credentials against a local secret (`/ppp secret`):
    /// `Some(success)` when they match, with the MS-CHAPv2 authenticator
    /// string when the method needs one.
    pub fn verify_local(&self, password: &str) -> Option<Option<[u8; AUTH_STRING_LEN]>> {
        match &self.method {
            AuthMethod::Pap { password: p } => auth::ct_eq(p, password.as_bytes()).then_some(None),
            AuthMethod::Chap {
                id,
                challenge,
                response,
            } => {
                auth::verify_chap_md5(*id, password.as_bytes(), challenge, response).then_some(None)
            }
            AuthMethod::MsChapV1 {
                challenge,
                response,
                ..
            } => auth::verify_mschap1(challenge, password, response).then_some(None),
            AuthMethod::MsChapV2 {
                challenge,
                response,
                ..
            } => auth::verify_mschap2(challenge, &self.username, password, response).map(Some),
        }
    }
}

/// An IPv4 assignment (local pool or RADIUS Framed-IP-Address).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Assignment {
    pub address: Ipv4Addr,
    pub dns: [Option<Ipv4Addr>; 2],
    pub nbns: [Option<Ipv4Addr>; 2],
}

/// The caller's yes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Authorization {
    /// MS-CHAPv2: the "S=…" string (local check or RADIUS MS-CHAP2-Success);
    /// required, the peer refuses a Success without it (RFC 2759 §5).
    pub mschap2_success: Option<[u8; AUTH_STRING_LEN]>,
    /// Text for the Success/Ack message.
    pub message: Box<[u8]>,
    /// Pre-assigned address; `None` = ask with [`Event::NeedAddress`].
    pub ipv4: Option<Ipv4Assignment>,
    pub rate_limit: Option<RateLimit>,
    /// Seconds until the session is closed.
    pub session_timeout: Option<u32>,
}

/// IPv6 of one session (RouterOS `/ppp profile use-ipv6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Ipv6Mode {
    /// No IPv6CP: a Configure-Request from the peer gets a Protocol-Reject
    /// (RFC 1661 §5.7).
    Off,
    /// IPv6CP runs; its failure leaves the session on IPv4.
    #[default]
    On,
    /// IPv6CP must open: its failure ends the session.
    Require,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthVerdict {
    Accept(Authorization),
    Reject { message: Box<[u8]> },
}

/// Why a session ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DownReason {
    /// The subscriber sent PADT.
    PeerPadt,
    /// The subscriber closed LCP (Terminate-Request).
    PeerTerminate,
    /// [`Server::terminate`].
    Admin,
    AuthFailed,
    /// No answer from the caller or no response from the subscriber.
    AuthTimeout,
    /// RFC 1661 §4.6 Max-Configure exhausted or LCP refused.
    LcpFailed,
    /// No network protocol could be opened (no address, NCPs failed).
    NcpFailed,
    /// LCP echo went unanswered (keepalive).
    Keepalive,
    /// Not up within `setup_timeout_ms`.
    SetupTimeout,
    /// The authorisation's Session-Timeout.
    SessionTimeout,
    /// one-session-per-host: a new session from the same host.
    Replaced,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Verify these credentials; answer with [`Server::auth_reply`].
    Authenticate {
        session: SessionRef,
        request: Box<AuthRequest>,
    },
    /// Give the subscriber an IPv4 address; answer with
    /// [`Server::address_reply`].
    NeedAddress { session: SessionRef },
    /// The first network protocol is up: install the session.
    Up {
        session: SessionRef,
        descriptor: Box<SessionDescriptor>,
    },
    /// A later network protocol came up (e.g. IPv6CP after IPCP).
    Changed {
        session: SessionRef,
        descriptor: Box<SessionDescriptor>,
    },
    /// The session is gone (always sent, up or not): release its address.
    Down {
        session: SessionRef,
        key: SessionKey,
        ipv4: Option<Ipv4Addr>,
        was_up: bool,
        reason: DownReason,
    },
}

/// Counters (RouterOS-style `print stats`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Stats {
    pub padi_rx: u64,
    pub padi_limited: u64,
    pub padi_refused: u64,
    /// PADIs and PADRs refused by the Service-Name table (drop rows, a
    /// row's max sessions or PADI limit).
    pub service_refused: u64,
    /// PADIs and PADRs refused because their VLAN holds `max_per_vlan`
    /// sessions (G4.3l).
    pub vlan_refused: u64,
    pub pado_tx: u64,
    pub pado_delayed: u64,
    pub padr_rx: u64,
    pub padr_bad_cookie: u64,
    pub padr_duplicate: u64,
    pub pads_tx: u64,
    pub pads_error: u64,
    pub padt_rx: u64,
    pub padt_tx: u64,
    pub sessions_created: u64,
    pub sessions_up: u64,
    pub auth_ok: u64,
    pub auth_fail: u64,
    pub keepalive_timeouts: u64,
    pub malformed: u64,
    pub unknown_session: u64,
    /// PADTs sent for frames of unknown sessions.
    pub padt_unknown: u64,
    pub ignored: u64,
}

pub type ServerOutput = Output<Event>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct HostKey {
    ifindex: u32,
    vlans: Vlans,
    mac: Mac,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Delayed {
    at: Millis,
    seq: u64,
    ifindex: u32,
    frame: Box<[u8]>,
}

/// Everything a session step may touch besides the session.
pub(crate) struct Env<'a> {
    pub now: Millis,
    pub cfg: &'a ServerConfig,
    pub out: &'a mut ServerOutput,
    pub scratch: &'a mut Scratch,
    pub rng: &'a mut Rng,
    pub stats: &'a mut Stats,
}

pub struct Server {
    cfg: ServerConfig,
    /// Index = SESSION_ID.
    sessions: Vec<Option<Box<Session>>>,
    /// FIFO, so a freed SID is reused as late as possible.
    free: VecDeque<u16>,
    active: usize,
    generation: u32,
    wheel: Wheel,
    due: Vec<Entry>,
    cookies: CookieJar,
    limiter: PadiLimiter,
    /// PADTs answering frames for sessions we do not have (100/s).
    padt_limiter: PadiLimiter,
    rng: Rng,
    by_host: HashMap<HostKey, u16>,
    by_uniq: HashMap<(HostKey, u64), u16>,
    delayed: BinaryHeap<Reverse<Delayed>>,
    delayed_seq: u64,
    scratch: Scratch,
    stats: Stats,
    /// Sessions and PADI limiters per row of `cfg.services`.
    svc: services::ServiceState,
    /// Sessions per (port, VLANs), kept only with `max_per_vlan`.
    per_vlan: HashMap<(u32, Vlans), u32>,
}

/// Identifies the PADR that created a session: Host-Uniq and AC-Cookie.
fn uniq_hash(host_uniq: Option<&[u8]>, cookie: Option<&[u8]>) -> u64 {
    let mut h = DefaultHasher::new();
    host_uniq.hash(&mut h);
    cookie.hash(&mut h);
    h.finish()
}

impl Server {
    /// `seed` keys the AC-Cookie and the challenge/magic generator; take it
    /// from the OS (`getrandom`).
    pub fn new(mut cfg: ServerConfig, seed: [u8; 32], now: Millis) -> Server {
        cfg.max_sessions = cfg.max_sessions.clamp(1, MAX_SID);
        let mut rng = Rng::new(seed);
        let own_key = rng.array::<32>();
        let cookie_key = cfg.cookie_secret.unwrap_or(own_key);
        let n = usize::from(cfg.max_sessions);
        Server {
            sessions: (0..=n).map(|_| None).collect(),
            free: cfg.sids().collect(),
            active: 0,
            generation: 0,
            wheel: Wheel::new(now),
            due: Vec::new(),
            cookies: CookieJar::new(cookie_key, cfg.cookie_timeout_ms),
            limiter: PadiLimiter::new(cfg.padi_limit, cfg.mac_padi_limit, cfg.mac_padi_burst),
            padt_limiter: PadiLimiter::new(100, 0, 0),
            rng,
            by_host: HashMap::new(),
            by_uniq: HashMap::new(),
            delayed: BinaryHeap::new(),
            delayed_seq: 0,
            scratch: Scratch::default(),
            stats: Stats::default(),
            svc: services::ServiceState::new(&cfg.services),
            per_vlan: HashMap::new(),
            cfg,
        }
    }

    pub fn config(&self) -> &ServerConfig {
        &self.cfg
    }

    /// Takes a new configuration for what comes next: new sessions, the
    /// PADI limits, PADO delays, timers of sessions not yet up. The MAC and
    /// the SESSION_ID space (`max_sessions`) stay: changing them is a new
    /// server.
    pub fn reconfigure(&mut self, mut cfg: ServerConfig) {
        cfg.ac_mac = self.cfg.ac_mac;
        cfg.max_sessions = self.cfg.max_sessions;
        cfg.sid_lane = self.cfg.sid_lane;
        let limits = (cfg.padi_limit, cfg.mac_padi_limit, cfg.mac_padi_burst);
        if limits
            != (
                self.cfg.padi_limit,
                self.cfg.mac_padi_limit,
                self.cfg.mac_padi_burst,
            )
        {
            self.limiter = PadiLimiter::new(limits.0, limits.1, limits.2);
        }
        if cfg.cookie_secret != self.cfg.cookie_secret
            && let Some(k) = cfg.cookie_secret
        {
            self.cookies.rotate(k);
        }
        let table = cfg.services != self.cfg.services;
        let per_vlan = (cfg.max_per_vlan > 0) != (self.cfg.max_per_vlan > 0);
        self.cfg = cfg;
        if per_vlan {
            self.per_vlan.clear();
            if self.cfg.max_per_vlan > 0 {
                for s in self.sessions.iter().flatten() {
                    *self.per_vlan.entry((s.ifindex, s.vlans)).or_default() += 1;
                }
            }
        }
        if table {
            // Rows moved: each session counts again under the row its name
            // lands on now (O(sessions), once per change of the table).
            self.svc = services::ServiceState::new(&self.cfg.services);
            for s in self.sessions.iter_mut().flatten() {
                let (slot, _) = self.cfg.services.lookup(&s.service);
                s.svc = slot;
                self.svc.add(slot);
            }
        }
    }

    /// Sessions held per row of the Service-Name table: `(name, sessions)`,
    /// the named rows in order, then `""` (empty) and `"*"` (any).
    pub fn service_sessions(&self) -> Vec<(Vec<u8>, u32)> {
        let n = |slot: ServiceSlot| self.svc.active.get(usize::from(slot)).copied().unwrap_or(0);
        let mut out: Vec<(Vec<u8>, u32)> = self
            .cfg
            .services
            .named()
            .enumerate()
            .map(|(i, (name, _))| {
                let slot = u16::try_from(i).map_or(services::ANY, |i| services::NAMED + i);
                (name.to_vec(), n(slot))
            })
            .collect();
        out.push((Vec::new(), n(services::EMPTY)));
        out.push((b"*".to_vec(), n(services::ANY)));
        out
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Sessions that hold a SESSION_ID (any phase).
    pub fn active(&self) -> usize {
        self.active
    }

    /// The port a cookie binds: none in a redundant pair (G4.3h).
    fn cookie_port(&self, ifindex: u32) -> u32 {
        if self.cfg.cookie_secret.is_some() {
            0
        } else {
            ifindex
        }
    }

    /// Installs a new AC-Cookie secret; cookies under the old one stay valid
    /// for `cookie_timeout_ms`.
    pub fn rotate_cookie_secret(&mut self, secret: [u8; 32]) {
        self.cookies.rotate(secret);
    }

    /// The earliest time [`Server::handle_timers`] has work.
    pub fn next_deadline(&self) -> Option<Millis> {
        let pado = self.delayed.peek().map(|Reverse(d)| d.at);
        match (self.wheel.next_deadline(), pado) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Descriptor of a live session.
    pub fn session(&self, sid: u16) -> Option<SessionDescriptor> {
        self.slot(sid).map(|s| s.descriptor(&self.cfg))
    }

    /// Live sessions' references, in SID order.
    pub fn sessions(&self) -> impl Iterator<Item = SessionRef> + '_ {
        self.sessions.iter().flatten().map(|s| s.reference())
    }

    fn slot(&self, sid: u16) -> Option<&Session> {
        self.sessions.get(usize::from(sid))?.as_deref()
    }

    fn env<'a>(
        now: Millis,
        cfg: &'a ServerConfig,
        out: &'a mut ServerOutput,
        scratch: &'a mut Scratch,
        rng: &'a mut Rng,
        stats: &'a mut Stats,
    ) -> Env<'a> {
        Env {
            now,
            cfg,
            out,
            scratch,
            rng,
            stats,
        }
    }

    /// Runs `f` on a live session named by `r` (or by SID with any
    /// generation), then frees or reschedules it.
    fn with_session(
        &mut self,
        now: Millis,
        sid: u16,
        gen_: Option<u32>,
        out: &mut ServerOutput,
        f: impl FnOnce(&mut Session, &mut Env<'_>),
    ) -> bool {
        let Some(Some(s)) = self.sessions.get_mut(usize::from(sid)) else {
            return false;
        };
        if gen_.is_some_and(|g| g != s.gen_) {
            return false;
        }
        let mut env = Self::env(
            now,
            &self.cfg,
            out,
            &mut self.scratch,
            &mut self.rng,
            &mut self.stats,
        );
        f(s, &mut env);
        let dead = s.dead;
        let next = s.next_deadline(&self.cfg);
        let gen_ = s.gen_;
        if let Some(reason) = dead {
            self.free_session(sid, reason, out);
        } else if let Some(d) = next
            && s.want_schedule(d, now)
        {
            self.wheel.insert(Entry {
                deadline: d,
                slot: u32::from(sid),
                gen_,
            });
        }
        true
    }

    fn free_session(&mut self, sid: u16, reason: DownReason, out: &mut ServerOutput) {
        let Some(slot) = self.sessions.get_mut(usize::from(sid)) else {
            return;
        };
        let Some(s) = slot.take() else {
            return;
        };
        self.active -= 1;
        self.free.push_back(sid);
        self.svc.remove(s.svc);
        if self.cfg.max_per_vlan > 0
            && let Some(n) = self.per_vlan.get_mut(&(s.ifindex, s.vlans))
        {
            *n = n.saturating_sub(1);
            if *n == 0 {
                self.per_vlan.remove(&(s.ifindex, s.vlans));
            }
        }
        let hk = s.host_key();
        if self.by_host.get(&hk) == Some(&sid) {
            self.by_host.remove(&hk);
        }
        let uk = (hk, s.uniq);
        if self.by_uniq.get(&uk) == Some(&sid) {
            self.by_uniq.remove(&uk);
        }
        out.events.push(Event::Down {
            session: s.reference(),
            key: s.key(),
            ipv4: s.assigned_ipv4(),
            was_up: s.up,
            reason,
        });
    }

    /// One received frame from `ifindex` (Ethernet header included).
    pub fn handle_frame(
        &mut self,
        now: Millis,
        ifindex: u32,
        frame: &[u8],
        out: &mut ServerOutput,
    ) {
        let Ok(e) = eth::parse(frame) else {
            self.stats.malformed += 1;
            return;
        };
        match e.ethertype {
            ETHERTYPE_DISCOVERY => match discovery::parse(frame) {
                Ok(d) => self.discovery(now, ifindex, &d, out),
                Err(_) => self.stats.malformed += 1,
            },
            ETHERTYPE_SESSION => match ppp::parse_session(frame) {
                Ok(f) => self.session_frame(now, ifindex, &f, out),
                Err(_) => self.stats.malformed += 1,
            },
            _ => self.stats.ignored += 1,
        }
    }

    fn session_frame(
        &mut self,
        now: Millis,
        ifindex: u32,
        f: &ppp::SessionFrame<'_>,
        out: &mut ServerOutput,
    ) {
        let sid = f.session_id;
        // RFC 2516 §6: the session is the MAC pair plus SESSION_ID; a frame
        // from anyone else (or another port/VLAN) is not this session's.
        let matches = self.slot(sid).is_some_and(|s| {
            s.client_mac == f.link.src
                && s.ifindex == ifindex
                && s.vlans.outer == f.link.vlans.outer
                && s.vlans.inner == f.link.vlans.inner
        });
        if !matches || f.link.dst != self.cfg.ac_mac {
            self.stats.unknown_session += 1;
            // A host still talking on a session we no longer have (our PADT
            // was lost): tell it, so it starts over instead of waiting for
            // its keepalive. Rate-limited: a spoofed source cannot turn us
            // into a PADT reflector.
            if f.link.dst == self.cfg.ac_mac
                && f.link.src.is_unicast()
                && sid != 0
                && !matches
                && self.padt_limiter.allow(now, Mac::ZERO)
            {
                let start = out.buf.len();
                let w = DiscoveryWriter::begin(
                    &mut out.buf,
                    f.link.src,
                    self.cfg.ac_mac,
                    f.link.vlans,
                    Code::Padt,
                    sid,
                );
                if w.finish().is_ok() {
                    out.push_frame(ifindex, start);
                    self.stats.padt_tx += 1;
                    self.stats.padt_unknown += 1;
                }
            }
            return;
        }
        let (protocol, info) = (f.protocol, f.info);
        self.with_session(now, sid, None, out, |s, env| s.receive(env, protocol, info));
    }

    fn discovery(&mut self, now: Millis, ifindex: u32, d: &Discovery<'_>, out: &mut ServerOutput) {
        if !d.src.is_unicast() || !self.cfg.vlans.allows(d.vlans) {
            self.stats.ignored += 1;
            return;
        }
        match d.code {
            Code::Padi => self.padi(now, ifindex, d, out),
            Code::Padr => self.padr(now, ifindex, d, out),
            Code::Padt => self.padt(now, ifindex, d, out),
            _ => self.stats.ignored += 1,
        }
    }

    /// The PADO/PADS tags every reply echoes (RFC 2516 §5.2: Host-Uniq and
    /// Relay-Session-Id unmodified; RFC 4638 §5: PPP-Max-Payload only when
    /// supported).
    fn echo_tags(&self, w: &mut DiscoveryWriter<'_>, d: &Discovery<'_>) {
        if let Some(h) = d.tags.host_uniq {
            w.tag(tag::HOST_UNIQ, h);
        }
        if let Some(r) = d.tags.relay_session_id {
            w.tag(tag::RELAY_SESSION_ID, r);
        }
        if let Some(v) = self.max_payload_for(d) {
            w.tag_u16(tag::PPP_MAX_PAYLOAD, v);
        }
    }

    fn max_payload_for(&self, d: &Discovery<'_>) -> Option<u16> {
        let v = d.tags.ppp_max_payload?;
        let cap = self.cfg.max_payload?;
        (v > DEFAULT_MRU && v <= cap).then_some(v)
    }

    /// The row has no room, unless `host` holds a session on it that
    /// one-session-per-host would replace.
    fn row_full(&self, host: HostKey, slot: ServiceSlot) -> bool {
        if !self.svc.full(&self.cfg.services, slot) {
            return false;
        }
        !self.replaces(host, |s| s.svc == slot)
    }

    /// The VLAN stack of `host` holds `max_per_vlan` sessions, none of
    /// them `host`'s own (which one-session-per-host would replace).
    fn vlan_full(&self, host: HostKey) -> bool {
        let max = self.cfg.max_per_vlan;
        if max == 0
            || self
                .per_vlan
                .get(&(host.ifindex, host.vlans))
                .is_none_or(|n| *n < max)
        {
            return false;
        }
        !self.replaces(host, |_| true)
    }

    /// `host` has a session that one-session-per-host would replace, and
    /// it passes `f`.
    fn replaces(&self, host: HostKey, f: impl Fn(&Session) -> bool) -> bool {
        self.cfg.one_session_per_host
            && self
                .by_host
                .get(&host)
                .and_then(|sid| self.slot(*sid))
                .is_some_and(f)
    }

    /// The server's load delay (accel-ppp `pado-delay`).
    fn pado_delay(&self) -> u32 {
        let n = self.active as u32;
        self.cfg
            .pado_delay
            .iter()
            .filter(|(at, _)| n >= *at)
            .map(|(_, d)| *d)
            .max()
            .unwrap_or(0)
    }

    fn padi(&mut self, now: Millis, ifindex: u32, d: &Discovery<'_>, out: &mut ServerOutput) {
        self.stats.padi_rx += 1;
        // RFC 2516 §5.1: broadcast, SESSION_ID 0, exactly one Service-Name.
        let addressed = d.dst == Mac::BROADCAST || d.dst == self.cfg.ac_mac;
        let Some(service) = d.tags.service_name else {
            self.stats.padi_refused += 1;
            return;
        };
        // RFC 2516 §5.2: answer only if we can serve the request.
        if !addressed || d.session_id != 0 || d.tags.service_names != 1 || self.free.is_empty() {
            self.stats.padi_refused += 1;
            return;
        }
        // G4.3k: the row of the name decides; drop, a full row and a row's
        // PADI limit all mean "cannot serve" (§5.2: no PADO).
        let (slot, rule) = self.cfg.services.lookup(service);
        let rule = *rule;
        let host = HostKey {
            ifindex,
            vlans: d.vlans,
            mac: d.src,
        };
        if rule.action == ServiceAction::Drop || self.row_full(host, slot) {
            self.stats.padi_refused += 1;
            self.stats.service_refused += 1;
            return;
        }
        // G4.3l: the VLAN holds its sessions already (§5.2: cannot serve).
        if self.vlan_full(host) {
            self.stats.padi_refused += 1;
            self.stats.vlan_refused += 1;
            return;
        }
        if !self.limiter.allow(now, d.src) {
            self.stats.padi_limited += 1;
            return;
        }
        if !self.svc.allow(now, slot, d.src) {
            self.stats.padi_limited += 1;
            self.stats.service_refused += 1;
            return;
        }
        let cookie = self
            .cookies
            .issue(now, d.src, self.cookie_port(ifindex), d.vlans);
        let row_delay = match rule.action {
            ServiceAction::Delay => rule.delay_ms,
            _ => 0,
        };
        let delay = self.pado_delay().saturating_add(row_delay);
        let start = out.buf.len();
        let mut w =
            DiscoveryWriter::begin(&mut out.buf, d.src, self.cfg.ac_mac, d.vlans, Code::Pado, 0);
        // RFC 2516 §5.2: AC-Name and the same Service-Name.
        w.tag(tag::AC_NAME, &self.cfg.ac_name);
        w.tag(tag::SERVICE_NAME, service);
        w.tag(tag::AC_COOKIE, &cookie);
        self.echo_tags(&mut w, d);
        if w.finish().is_err() {
            return;
        }
        self.stats.pado_tx += 1;
        if delay == 0 {
            out.push_frame(ifindex, start);
            return;
        }
        // accel-ppp pado-delay: busy servers answer later, so clients that
        // see several ACs pick a lighter one.
        let frame: Box<[u8]> = out.buf.get(start..).unwrap_or(&[]).into();
        out.buf.truncate(start);
        if self.delayed.len() >= self.cfg.pado_queue {
            return;
        }
        self.stats.pado_delayed += 1;
        self.delayed_seq += 1;
        self.delayed.push(Reverse(Delayed {
            at: now + u64::from(delay),
            seq: self.delayed_seq,
            ifindex,
            frame,
        }));
    }

    fn pads_error(
        &mut self,
        ifindex: u32,
        d: &Discovery<'_>,
        kind: u16,
        msg: &[u8],
        out: &mut ServerOutput,
    ) {
        // RFC 2516 §5.4: an error PADS carries SESSION_ID 0.
        let start = out.buf.len();
        let mut w =
            DiscoveryWriter::begin(&mut out.buf, d.src, self.cfg.ac_mac, d.vlans, Code::Pads, 0);
        if let Some(s) = d.tags.service_name {
            w.tag(tag::SERVICE_NAME, s);
        }
        w.tag(kind, msg);
        self.echo_tags(&mut w, d);
        if w.finish().is_ok() {
            out.push_frame(ifindex, start);
            self.stats.pads_error += 1;
        }
    }

    fn send_pads(&mut self, ifindex: u32, d: &Discovery<'_>, sid: u16, out: &mut ServerOutput) {
        let start = out.buf.len();
        let mut w = DiscoveryWriter::begin(
            &mut out.buf,
            d.src,
            self.cfg.ac_mac,
            d.vlans,
            Code::Pads,
            sid,
        );
        w.tag(tag::SERVICE_NAME, d.tags.service_name.unwrap_or(&[]));
        w.tag(tag::AC_NAME, &self.cfg.ac_name);
        self.echo_tags(&mut w, d);
        if w.finish().is_ok() {
            out.push_frame(ifindex, start);
            self.stats.pads_tx += 1;
        }
    }

    fn padr(&mut self, now: Millis, ifindex: u32, d: &Discovery<'_>, out: &mut ServerOutput) {
        self.stats.padr_rx += 1;
        if d.dst != self.cfg.ac_mac || d.session_id != 0 {
            self.stats.ignored += 1;
            return;
        }
        let host = HostKey {
            ifindex,
            vlans: d.vlans,
            mac: d.src,
        };
        let uniq = uniq_hash(d.tags.host_uniq, d.tags.ac_cookie);
        // A copy of the PADR that created a session (retransmitted because
        // our PADS was lost, or duplicated on the wire and late) gets the
        // same SESSION_ID. The cookie makes it the same request: a host that
        // starts over sends a new PADI and brings a new cookie. Checked
        // before the cookie's age: we validated these exact bytes when the
        // session was made. Without cookies, only before LCP starts.
        let same_request = |s: &Session| d.tags.ac_cookie.is_some() || s.in_discovery();
        if let Some(&sid) = self.by_uniq.get(&(host, uniq))
            && self.slot(sid).is_some_and(same_request)
        {
            self.stats.padr_duplicate += 1;
            self.send_pads(ifindex, d, sid, out);
            return;
        }
        // RFC 2516 §9: no valid cookie, no state.
        let cookie_ok = d.tags.ac_cookie.is_some_and(|c| {
            self.cookies
                .verify(now, c, d.src, self.cookie_port(ifindex), d.vlans)
        });
        if self.cfg.require_cookie && !cookie_ok {
            self.stats.padr_bad_cookie += 1;
            return;
        }
        // RFC 2516 §5.3: exactly one Service-Name; §5.4: one we do not
        // offer (a drop row) gets Service-Name-Error. Erratum 5634: the
        // error text is not NUL-terminated.
        let lookup = d
            .tags
            .service_name
            .filter(|_| d.tags.service_names == 1)
            .map(|s| (s, self.cfg.services.lookup(s)));
        let (service, slot) = match lookup {
            Some((s, (slot, r))) if r.action != ServiceAction::Drop => (s, slot),
            _ => {
                self.stats.service_refused += u64::from(lookup.is_some());
                self.pads_error(
                    ifindex,
                    d,
                    tag::SERVICE_NAME_ERROR,
                    b"unsupported service",
                    out,
                );
                return;
            }
        };
        // The row's max sessions: §5.4 AC-System-Error ("insufficient
        // resources"), as for the server's. A host coming back on its own
        // row takes its old session's place.
        if self.row_full(host, slot) {
            self.stats.service_refused += 1;
            self.pads_error(
                ifindex,
                d,
                tag::AC_SYSTEM_ERROR,
                b"service session limit",
                out,
            );
            return;
        }
        if self.vlan_full(host) {
            self.stats.vlan_refused += 1;
            self.pads_error(ifindex, d, tag::AC_SYSTEM_ERROR, b"VLAN session limit", out);
            return;
        }
        if self.cfg.one_session_per_host
            && let Some(&old) = self.by_host.get(&host)
        {
            self.with_session(now, old, None, out, |s, env| s.replace(env));
        }
        let Some(sid) = self.free.pop_front() else {
            // §5.4: AC-System-Error, "insufficient resources".
            self.pads_error(ifindex, d, tag::AC_SYSTEM_ERROR, b"session limit", out);
            return;
        };
        self.generation = self.generation.wrapping_add(1);
        let mru_cap = self.max_payload_for(d);
        let s = Session::new(
            &self.cfg,
            &mut self.rng,
            session::Init {
                gen_: self.generation,
                sid,
                ifindex,
                vlans: d.vlans,
                client_mac: d.src,
                uniq,
                mru_cap,
                service: service.into(),
                svc: slot,
                circuit_id: d.tags.circuit_id.map(Into::into),
                remote_id: d.tags.remote_id.map(Into::into),
            },
            now,
        );
        if let Some(slot) = self.sessions.get_mut(usize::from(sid)) {
            *slot = Some(Box::new(s));
        }
        self.active += 1;
        self.svc.add(slot);
        if self.cfg.max_per_vlan > 0 {
            *self.per_vlan.entry((ifindex, d.vlans)).or_default() += 1;
        }
        self.stats.sessions_created += 1;
        self.by_host.insert(host, sid);
        self.by_uniq.insert((host, uniq), sid);
        self.send_pads(ifindex, d, sid, out);
        self.with_session(now, sid, None, out, |s, env| s.start(env));
    }

    fn padt(&mut self, _now: Millis, ifindex: u32, d: &Discovery<'_>, out: &mut ServerOutput) {
        self.stats.padt_rx += 1;
        let sid = d.session_id;
        let ours = self.slot(sid).is_some_and(|s| {
            s.client_mac == d.src && s.ifindex == ifindex && s.vlans.outer == d.vlans.outer
        });
        if ours && d.dst == self.cfg.ac_mac {
            // RFC 2516 §5.5: no PPP traffic after a PADT, not even LCP
            // Terminate: the session ends here.
            self.free_session(sid, DownReason::PeerPadt, out);
        } else {
            self.stats.unknown_session += 1;
        }
    }

    /// Fires due timers and delayed PADOs.
    pub fn handle_timers(&mut self, now: Millis, out: &mut ServerOutput) {
        while self.delayed.peek().is_some_and(|Reverse(d)| d.at <= now) {
            if let Some(Reverse(d)) = self.delayed.pop() {
                let start = out.buf.len();
                out.buf.extend_from_slice(&d.frame);
                out.push_frame(d.ifindex, start);
            }
        }
        let mut due = std::mem::take(&mut self.due);
        due.clear();
        self.wheel.expire(now, &mut due);
        for e in &due {
            let Ok(sid) = u16::try_from(e.slot) else {
                continue;
            };
            let live = self
                .slot(sid)
                .is_some_and(|s| s.gen_ == e.gen_ && s.fire(e.deadline));
            if live {
                self.with_session(now, sid, Some(e.gen_), out, |s, env| s.timers(env));
            }
        }
        self.due = due;
    }

    /// The answer to [`Event::Authenticate`].
    pub fn auth_reply(
        &mut self,
        now: Millis,
        session: SessionRef,
        verdict: AuthVerdict,
        out: &mut ServerOutput,
    ) -> bool {
        self.with_session(now, session.sid, Some(session.gen_), out, |s, env| {
            s.auth_verdict(env, verdict)
        })
    }

    /// IPv6 for one session, from its profile. Call before
    /// [`Server::auth_reply`] (the NCPs open with the verdict); later it
    /// only changes how a failure of IPv6CP is taken. `On` needs
    /// [`ServerConfig::ipv6`].
    pub fn set_ipv6(
        &mut self,
        now: Millis,
        session: SessionRef,
        mode: Ipv6Mode,
        out: &mut ServerOutput,
    ) -> bool {
        let allowed = self.cfg.ipv6;
        self.with_session(now, session.sid, Some(session.gen_), out, |s, _env| {
            s.v6_mode = if allowed { mode } else { Ipv6Mode::Off };
        })
    }

    /// The answer to [`Event::NeedAddress`]; `None` = no address available.
    pub fn address_reply(
        &mut self,
        now: Millis,
        session: SessionRef,
        ipv4: Option<Ipv4Assignment>,
        out: &mut ServerOutput,
    ) -> bool {
        self.with_session(now, session.sid, Some(session.gen_), out, |s, env| {
            s.address(env, ipv4)
        })
    }

    /// Closes a session (RouterOS "remove" of an active connection): LCP
    /// Terminate, then PADT.
    pub fn terminate(&mut self, now: Millis, session: SessionRef, out: &mut ServerOutput) -> bool {
        self.with_session(now, session.sid, Some(session.gen_), out, |s, env| {
            s.close(env, DownReason::Admin)
        })
    }

    /// Cross-checks the indexes (tests and debug builds of the service).
    #[doc(hidden)]
    pub fn check_invariants(&self) -> Result<(), String> {
        let live = self.sessions.iter().flatten().count();
        if live != self.active {
            return Err(format!("active {} != live {live}", self.active));
        }
        let own = self.cfg.sids().count();
        if live + self.free.len() != own {
            return Err(format!(
                "live {live} + free {} != {own} SESSION_IDs of lane {:?}",
                self.free.len(),
                self.cfg.sid_lane
            ));
        }
        let mut seen = vec![false; usize::from(MAX_SID) + 1];
        for sid in &self.free {
            let Some(flag) = seen.get_mut(usize::from(*sid)) else {
                return Err(format!("free SID {sid} out of range"));
            };
            if *flag || *sid == 0 {
                return Err(format!("SID {sid} free twice or zero"));
            }
            *flag = true;
            if self.slot(*sid).is_some() {
                return Err(format!("SID {sid} free and in use"));
            }
        }
        for (sid, s) in self.sessions.iter().enumerate() {
            if let Some(s) = s
                && usize::from(s.sid) != sid
            {
                return Err(format!("session at {sid} says SID {}", s.sid));
            }
        }
        for (k, sid) in &self.by_host {
            if self.slot(*sid).is_none_or(|s| s.host_key() != *k) {
                return Err(format!("by_host points at a dead SID {sid}"));
            }
        }
        for ((k, u), sid) in &self.by_uniq {
            if self
                .slot(*sid)
                .is_none_or(|s| s.host_key() != *k || s.uniq != *u)
            {
                return Err(format!("by_uniq points at a dead SID {sid}"));
            }
        }
        let mut rows = vec![0u32; self.cfg.services.slots()];
        for s in self.sessions.iter().flatten() {
            if let Some(n) = rows.get_mut(usize::from(s.svc)) {
                *n += 1;
            }
        }
        if self.cfg.max_per_vlan > 0 {
            let mut v: HashMap<(u32, Vlans), u32> = HashMap::new();
            for s in self.sessions.iter().flatten() {
                *v.entry((s.ifindex, s.vlans)).or_default() += 1;
            }
            if v != self.per_vlan {
                return Err("sessions per VLAN out of step".into());
            }
        }
        if rows != self.svc.active {
            return Err(format!(
                "sessions per service {:?} != counted {rows:?}",
                self.svc.active
            ));
        }
        if self.cfg.one_session_per_host {
            let mut hosts = std::collections::HashSet::new();
            for s in self.sessions.iter().flatten() {
                if !hosts.insert(s.host_key()) {
                    return Err(format!("two sessions for host {}", s.client_mac));
                }
            }
        }
        Ok(())
    }

    /// Heap bytes owned per live session, for the memory benchmark.
    #[doc(hidden)]
    pub fn session_bytes() -> usize {
        std::mem::size_of::<Session>()
    }
}

#[cfg(test)]
mod tests;

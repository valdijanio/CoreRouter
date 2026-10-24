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

/// RFC 2516 §4: SESSION_ID 0xffff is reserved, 0 means "no session".
pub const MAX_SID: u16 = 0xfffe;

/// Which outer VLANs the server answers (RouterOS v7 `pppoe-over-vlan-range`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum VlanFilter {
    #[default]
    Any,
    Untagged,
    Ranges(Vec<RangeInclusive<u16>>),
}

impl VlanFilter {
    pub fn allows(&self, v: Vlans) -> bool {
        match self {
            VlanFilter::Any => true,
            VlanFilter::Untagged => !v.is_tagged(),
            VlanFilter::Ranges(r) => r.iter().any(|r| r.contains(&v.outer)),
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
    /// Services offered; empty = any (RouterOS `service-name` unset).
    pub service_names: Vec<Vec<u8>>,
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
    /// Run IPv6CP (interface ids only; prefixes are G4.3e).
    pub ipv6: bool,
    /// How long an authentication or address answer may take (RADIUS
    /// timeouts × retries fit under it).
    pub answer_timeout_ms: u64,
    /// PADS to first network protocol up.
    pub setup_timeout_ms: u64,
    /// Delayed PADOs held at most.
    pub pado_queue: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            ac_mac: Mac([0x02, 0, 0, 0, 0, 1]),
            ac_name: b"CoreRouter".to_vec(),
            service_names: Vec::new(),
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
            answer_timeout_ms: 30_000,
            setup_timeout_ms: 60_000,
            pado_queue: 4096,
        }
    }
}

/// Names a session across asynchronous answers: a stale reference (the
/// session ended, the SID was reused) is ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
    rng: Rng,
    by_host: HashMap<HostKey, u16>,
    by_uniq: HashMap<(HostKey, u64), u16>,
    delayed: BinaryHeap<Reverse<Delayed>>,
    delayed_seq: u64,
    scratch: Scratch,
    stats: Stats,
}

fn uniq_hash(v: Option<&[u8]>) -> u64 {
    let mut h = DefaultHasher::new();
    v.hash(&mut h);
    h.finish()
}

impl Server {
    /// `seed` keys the AC-Cookie and the challenge/magic generator; take it
    /// from the OS (`getrandom`).
    pub fn new(mut cfg: ServerConfig, seed: [u8; 32], now: Millis) -> Server {
        cfg.max_sessions = cfg.max_sessions.clamp(1, MAX_SID);
        let mut rng = Rng::new(seed);
        let cookie_key = rng.array::<32>();
        let n = usize::from(cfg.max_sessions);
        Server {
            sessions: (0..=n).map(|_| None).collect(),
            free: (1..=cfg.max_sessions).collect(),
            active: 0,
            generation: 0,
            wheel: Wheel::new(now),
            due: Vec::new(),
            cookies: CookieJar::new(cookie_key, cfg.cookie_timeout_ms),
            limiter: PadiLimiter::new(cfg.padi_limit, cfg.mac_padi_limit, cfg.mac_padi_burst),
            rng,
            by_host: HashMap::new(),
            by_uniq: HashMap::new(),
            delayed: BinaryHeap::new(),
            delayed_seq: 0,
            scratch: Scratch::default(),
            stats: Stats::default(),
            cfg,
        }
    }

    pub fn config(&self) -> &ServerConfig {
        &self.cfg
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Sessions that hold a SESSION_ID (any phase).
    pub fn active(&self) -> usize {
        self.active
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

    fn service_ok(&self, name: &[u8]) -> bool {
        name.is_empty()
            || self.cfg.service_names.is_empty()
            || self.cfg.service_names.iter().any(|s| s == name)
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
        if !addressed
            || d.session_id != 0
            || d.tags.service_names != 1
            || !self.service_ok(service)
            || self.free.is_empty()
        {
            self.stats.padi_refused += 1;
            return;
        }
        if !self.limiter.allow(now, d.src) {
            self.stats.padi_limited += 1;
            return;
        }
        let cookie = self.cookies.issue(now, d.src, ifindex, d.vlans);
        let delay = self.pado_delay();
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
        // RFC 2516 §9: no valid cookie, no state.
        let cookie_ok = d
            .tags
            .ac_cookie
            .is_some_and(|c| self.cookies.verify(now, c, d.src, ifindex, d.vlans));
        if self.cfg.require_cookie && !cookie_ok {
            self.stats.padr_bad_cookie += 1;
            return;
        }
        let host = HostKey {
            ifindex,
            vlans: d.vlans,
            mac: d.src,
        };
        let uniq = uniq_hash(d.tags.host_uniq);
        // A retransmitted PADR (our PADS was lost) gets the same SESSION_ID
        // while that session has not started LCP from the peer's side.
        if let Some(&sid) = self.by_uniq.get(&(host, uniq))
            && self.slot(sid).is_some_and(|s| s.in_discovery())
        {
            self.stats.padr_duplicate += 1;
            self.send_pads(ifindex, d, sid, out);
            return;
        }
        // RFC 2516 §5.3: exactly one Service-Name; §5.4: one we do not
        // offer gets Service-Name-Error.
        let service = match (d.tags.service_name, d.tags.service_names) {
            (Some(s), 1) if self.service_ok(s) => s,
            _ => {
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
                circuit_id: d.tags.circuit_id.map(Into::into),
                remote_id: d.tags.remote_id.map(Into::into),
            },
            now,
        );
        if let Some(slot) = self.sessions.get_mut(usize::from(sid)) {
            *slot = Some(Box::new(s));
        }
        self.active += 1;
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
        if live + self.free.len() != usize::from(self.cfg.max_sessions) {
            return Err(format!(
                "live {live} + free {} != max {}",
                self.free.len(),
                self.cfg.max_sessions
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

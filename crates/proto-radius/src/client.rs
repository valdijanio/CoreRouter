//! Sans-IO RADIUS client (the NAS side).
//!
//! The caller owns the sockets and the clock:
//!
//! 1. submit with [`Client::access`] / [`Client::accounting`];
//! 2. send what [`Client::poll_transmit`] returns, from the socket it names
//!    (`server`, `socket`): the caller binds one UDP socket per pair the
//!    first time it sees it, so each socket has its own 256 identifiers;
//! 3. feed received datagrams to [`Client::handle_input`];
//! 4. call [`Client::handle_timeout`] when [`Client::poll_timeout`] says;
//! 5. drain [`Client::poll_event`].
//!
//! Behaviour, with the rule each part follows:
//!
//! - Identifiers: never reused on a socket while a request is outstanding
//!   (RFC 5080 §2.2.2), allocated round robin (close to the LRU the RFC
//!   recommends). When every socket of a server is full a new socket is
//!   used, up to [`ClientConfig::max_sockets`]; past that requests wait in
//!   a queue.
//! - Retransmission: RFC 5080 §2.2.1 (RT = IRT ± 10 %, doubling, capped by
//!   MRT ± 10 %; MRC transmissions or MRD milliseconds per server). A
//!   retransmission to the same server is byte for byte the same packet
//!   (same identifier and authenticator, RFC 5176 §2.3 and RFC 2865 §3).
//! - Failover: after MRC/MRD a request moves to the next server with a new
//!   identifier and authenticator. Access requests fail after one round of
//!   the servers; accounting goes round again until acknowledged (RFC 5080
//!   §2.2.1 "until the request is acknowledged") or until
//!   [`ClientConfig::accounting_max_age_ms`]. Acct-Delay-Time is added per
//!   server attempt (RFC 2866 §5.2: changing it changes the identifier).
//! - Dead servers: after [`ClientConfig::dead_after`] failed exchanges in a
//!   row a server is skipped; it is probed with Status-Server (RFC 5997)
//!   when enabled, or retried after [`ClientConfig::dead_time_ms`]. When
//!   every server is dead requests still go to one of them.
//! - Blast-RADIUS (CVE-2024-3596): every Access-Request and Status-Server
//!   carries a Message-Authenticator as its first attribute, and by default
//!   an Access-Accept/Reject/Challenge without a valid one is discarded
//!   (MikroTik `require-message-auth=yes-for-request-resp`).
//! - Interim-Update superseding: an interim submitted with a key replaces a
//!   still-pending interim with the same key (the counters are cumulative),
//!   so a server outage does not pile up stale interims.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, VecDeque};
use std::net::SocketAddr;

use thiserror::Error;

use crate::crypto::{self, MaCheck};
use crate::packet::{AttrList, Builder, Code, HEADER_LEN, MAX_PACKET_LEN, Packet, PushAttr, attr};

/// RFC 5080 §2.2.1 retransmission variables, in milliseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Retry {
    /// Initial retransmission time.
    pub irt_ms: u64,
    /// Maximum retransmission time (0 = no cap).
    pub mrt_ms: u64,
    /// Transmissions per server (0 = bounded by MRD only).
    pub mrc: u32,
    /// Duration per server (0 = bounded by MRC only).
    pub mrd_ms: u64,
}

impl Retry {
    /// Authentication: 1.1 s like RouterOS's `timeout`, 3 transmissions,
    /// at most 8 s per server (the user is waiting, RFC 2865 §2.4).
    pub const ACCESS: Self = Self {
        irt_ms: 1100,
        mrt_ms: 4400,
        mrc: 3,
        mrd_ms: 8000,
    };
    /// Accounting: the RFC 5080 defaults (IRT 2 s, MRT 16 s, MRD 30 s)
    /// per server, then failover and more rounds.
    pub const ACCOUNTING: Self = Self {
        irt_ms: 2000,
        mrt_ms: 16_000,
        mrc: 5,
        mrd_ms: 30_000,
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    Auth,
    Acct,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub addr: SocketAddr,
    pub secret: Vec<u8>,
    pub service: Service,
    pub retry: Retry,
    /// Probe with Status-Server while dead (RFC 5997 §4.1 watchdog, §4.3
    /// failover). Off by default, as §4.1 says: old servers ignore it.
    pub status_server: bool,
}

impl ServerConfig {
    pub fn auth(addr: SocketAddr, secret: &[u8]) -> Self {
        Self {
            addr,
            secret: secret.to_vec(),
            service: Service::Auth,
            retry: Retry::ACCESS,
            status_server: false,
        }
    }

    pub fn acct(addr: SocketAddr, secret: &[u8]) -> Self {
        Self {
            addr,
            secret: secret.to_vec(),
            service: Service::Acct,
            retry: Retry::ACCOUNTING,
            status_server: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientConfig {
    /// Discard Access-Accept/Reject/Challenge without a valid
    /// Message-Authenticator (Blast-RADIUS). Default on.
    pub require_message_authenticator: bool,
    /// Sockets (×256 identifiers) per server. Default 16 (4096 in flight).
    pub max_sockets: u16,
    /// Failed exchanges in a row before a server is considered dead.
    pub dead_after: u32,
    /// How long a dead server is skipped without Status-Server.
    pub dead_time_ms: u64,
    /// Interval between Status-Server probes of a dead server.
    pub probe_interval_ms: u64,
    /// Requests in flight plus queued (back-pressure).
    pub max_pending: usize,
    /// Give up on an accounting request this old (0 = never).
    pub accounting_max_age_ms: u64,
    /// NAS-Identifier sent in Status-Server (RFC 5997 §3 wants a NAS
    /// identification attribute).
    pub nas_identifier: String,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            require_message_authenticator: true,
            max_sockets: 16,
            dead_after: 3,
            dead_time_ms: 30_000,
            probe_interval_ms: 10_000,
            max_pending: 200_000,
            accounting_max_age_ms: 0,
            nas_identifier: "corerouter".into(),
        }
    }
}

/// Handle of a submitted request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RequestId(u64);

impl RequestId {
    fn new(slot: u32, gen_: u32) -> Self {
        Self(u64::from(gen_) << 32 | u64::from(slot))
    }

    fn slot(self) -> u32 {
        self.0 as u32
    }

    fn generation(self) -> u32 {
        (self.0 >> 32) as u32
    }

    pub fn as_u64(self) -> u64 {
        self.0
    }
}

/// Which local socket: the server it talks to and its index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SocketKey {
    pub server: usize,
    pub socket: u16,
}

/// A datagram to send; the bytes were written to the caller's buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transmit {
    pub from: SocketKey,
    pub dest: SocketAddr,
    pub request: RequestId,
    pub identifier: u8,
    /// Same bytes as the previous transmission of this request.
    pub retransmission: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// Every server was tried (or the accounting age limit passed).
    Timeout,
    /// Replaced by a newer interim with the same key.
    Superseded,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A valid response (authenticators checked).
    Response {
        request: RequestId,
        server: usize,
        code: Code,
        /// The response packet (parse it with [`Packet::parse`]).
        packet: Vec<u8>,
        /// The authenticator of the request it answers (needed to decrypt
        /// MS-MPPE keys and Tunnel-Password, RFC 2548 §2.4.2).
        request_authenticator: [u8; 16],
        rtt_ms: u64,
    },
    Failed {
        request: RequestId,
        reason: Failure,
    },
    ServerDown {
        server: usize,
    },
    ServerUp {
        server: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SubmitError {
    #[error("no server configured for this service")]
    NoServer,
    #[error("too many pending requests")]
    Busy,
    #[error("request too large: {0}")]
    Encode(#[from] crate::EncodeError),
}

/// Why a received datagram was dropped (counted, never answered).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Discard {
    #[error("unknown socket")]
    UnknownSocket,
    #[error("source address is not the server")]
    WrongSource,
    #[error("malformed packet")]
    Malformed,
    #[error("no request outstanding with this identifier")]
    Unsolicited,
    #[error("response code does not answer the request")]
    WrongCode,
    #[error("bad Response Authenticator")]
    BadAuthenticator,
    #[error("Message-Authenticator missing or invalid")]
    BadMessageAuthenticator,
}

/// Per-server counters, like RouterOS `/radius monitor`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ServerStats {
    pub requests: u64,
    pub accepts: u64,
    pub rejects: u64,
    pub challenges: u64,
    pub acct_responses: u64,
    pub resends: u64,
    /// Exchanges that ran out of MRC/MRD on this server.
    pub timeouts: u64,
    pub bad_replies: u64,
    pub unsolicited: u64,
    pub last_rtt_ms: u64,
    /// The first timeout new requests get now (adaptive, RFC 6298).
    pub rto_ms: u64,
    pub in_flight: u64,
    pub sockets: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Access,
    Accounting,
    /// Status-Server probe of one server.
    Status,
}

#[derive(Debug, Clone)]
struct Flight {
    socket: u16,
    id: u8,
    authenticator: [u8; 16],
    wire: Vec<u8>,
    tx: u32,
    first_tx_ms: u64,
    last_tx_ms: u64,
    rt_ms: u64,
}

#[derive(Debug, Clone)]
struct Pending {
    generation: u32,
    kind: Kind,
    attrs: AttrList,
    password: Option<Vec<u8>>,
    supersede: Option<u64>,
    created_ms: u64,
    server: usize,
    tried: u64,
    flight: Option<Flight>,
    /// Bumped on every (re)transmission: stale timers and queue entries
    /// carry an older value.
    seq: u32,
}

#[derive(Debug, Clone)]
struct IdTable {
    owner: Vec<u32>,
    free: u16,
    cursor: u8,
}

const FREE: u32 = u32::MAX;

impl IdTable {
    fn new() -> Self {
        Self {
            owner: vec![FREE; 256],
            free: 256,
            cursor: 0,
        }
    }

    fn alloc(&mut self, slot: u32) -> Option<u8> {
        if self.free == 0 {
            return None;
        }
        for k in 0..=255u8 {
            let id = self.cursor.wrapping_add(k);
            if let Some(o) = self.owner.get_mut(usize::from(id))
                && *o == FREE
            {
                *o = slot;
                self.free -= 1;
                self.cursor = id.wrapping_add(1);
                return Some(id);
            }
        }
        None
    }

    fn release(&mut self, id: u8, slot: u32) {
        if let Some(o) = self.owner.get_mut(usize::from(id))
            && *o == slot
        {
            *o = FREE;
            self.free += 1;
        }
    }

    fn owner(&self, id: u8) -> Option<u32> {
        self.owner
            .get(usize::from(id))
            .copied()
            .filter(|&o| o != FREE)
    }
}

#[derive(Debug, Clone)]
struct ServerState {
    cfg: ServerConfig,
    alive: bool,
    dead_until_ms: u64,
    next_probe_ms: Option<u64>,
    probing: bool,
    failures: u32,
    sockets: Vec<IdTable>,
    queue: VecDeque<(u32, u32)>,
    stats: ServerStats,
    /// Smoothed answer time and its variation (RFC 6298 §2), from answers
    /// to requests sent once (Karn: after a retransmission the answer may be
    /// to either copy). It follows a server that slows down gradually, as a
    /// queue does in a wave; one always slower than the IRT keeps the IRT
    /// (raise `timeout`, as on RouterOS). Measuring retransmitted requests
    /// from the first copy was tried: under 3 % loss it pinned the timeout
    /// at MRT and slowed failover.
    srtt_ms: Option<f64>,
    rttvar_ms: f64,
}

impl ServerState {
    /// The first timeout of a new request: the configured IRT, or more when
    /// this server is answering slower than that (SRTT + 4·RTTVAR, RFC
    /// 6298 §2.3), at most MRT. A loaded server is not sent copies of what
    /// it is still working on (G4.3g: at a 1.4 s answer time a fixed 1.1 s
    /// sent every request twice).
    fn first_rt(&self) -> u64 {
        let irt = self.cfg.retry.irt_ms;
        let est = self
            .srtt_ms
            .map_or(0.0, |srtt| srtt + 4.0 * self.rttvar_ms)
            .ceil() as u64;
        let rt = irt.max(est);
        match self.cfg.retry.mrt_ms {
            0 => rt,
            mrt => rt.min(mrt),
        }
    }

    /// RFC 6298 §2.2/§2.3 with α = 1/8, β = 1/4.
    fn sample(&mut self, rtt_ms: u64) {
        let r = rtt_ms as f64;
        match self.srtt_ms {
            None => {
                self.srtt_ms = Some(r);
                self.rttvar_ms = r / 2.0;
            }
            Some(srtt) => {
                self.rttvar_ms = 0.75 * self.rttvar_ms + 0.25 * (srtt - r).abs();
                self.srtt_ms = Some(0.875 * srtt + 0.125 * r);
            }
        }
        self.stats.rto_ms = self.first_rt();
    }
}

/// Maximum servers (the tried-set is a 64-bit mask).
pub const MAX_SERVERS: usize = 64;

pub struct Client {
    cfg: ClientConfig,
    servers: Vec<ServerState>,
    slots: Vec<Option<Pending>>,
    free_slots: Vec<u32>,
    next_gen: u32,
    timers: BinaryHeap<Reverse<(u64, u32, u32)>>,
    transmits: VecDeque<(u32, u32)>,
    events: VecDeque<Event>,
    supersede: HashMap<u64, RequestId>,
    pending: usize,
    seed: [u8; 32],
    counter: u64,
    rng: u64,
    /// Servers whose queue may move (an identifier was freed).
    pending_drain: Vec<usize>,
    last_now_ms: u64,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("servers", &self.servers.len())
            .field("pending", &self.pending)
            .finish_non_exhaustive()
    }
}

impl Client {
    /// `seed` keys the authenticator generator (RFC 2865 §3: Request
    /// Authenticators must be unpredictable and unique): pass 32 bytes from
    /// the OS random source. Servers past [`MAX_SERVERS`] are ignored.
    pub fn new(cfg: ClientConfig, servers: Vec<ServerConfig>, seed: [u8; 32]) -> Self {
        let d = crypto::md5(&[&seed, b"jitter"]);
        let mut r8 = [7u8; 8];
        r8.copy_from_slice(d.get(..8).unwrap_or(&[7; 8]));
        let rng = u64::from_le_bytes(r8);
        Self {
            cfg,
            servers: servers
                .into_iter()
                .take(MAX_SERVERS)
                .map(|cfg| ServerState {
                    cfg,
                    alive: true,
                    dead_until_ms: 0,
                    next_probe_ms: None,
                    probing: false,
                    failures: 0,
                    sockets: Vec::new(),
                    queue: VecDeque::new(),
                    stats: ServerStats::default(),
                    srtt_ms: None,
                    rttvar_ms: 0.0,
                })
                .collect(),
            slots: Vec::new(),
            free_slots: Vec::new(),
            next_gen: 1,
            timers: BinaryHeap::new(),
            transmits: VecDeque::new(),
            events: VecDeque::new(),
            supersede: HashMap::new(),
            pending: 0,
            seed,
            counter: 0,
            rng: rng | 1,
            pending_drain: Vec::new(),
            last_now_ms: 0,
        }
    }

    pub fn config(&self) -> &ClientConfig {
        &self.cfg
    }

    pub fn server_count(&self) -> usize {
        self.servers.len()
    }

    pub fn server(&self, i: usize) -> Option<&ServerConfig> {
        self.servers.get(i).map(|s| &s.cfg)
    }

    pub fn is_alive(&self, i: usize) -> bool {
        self.servers.get(i).is_some_and(|s| s.alive)
    }

    pub fn stats(&self, i: usize) -> Option<ServerStats> {
        self.servers.get(i).map(|s| {
            let mut st = s.stats;
            st.sockets = s.sockets.len() as u64;
            st
        })
    }

    /// Requests not yet answered or failed.
    pub fn pending(&self) -> usize {
        self.pending
    }

    /// Submit an Access-Request. `password` (PAP) is hidden per
    /// transmission with that server's secret (RFC 2865 §5.2); CHAP and
    /// MS-CHAP attributes go in `attrs` as they are secret-independent.
    pub fn access(
        &mut self,
        attrs: AttrList,
        password: Option<&[u8]>,
        now_ms: u64,
    ) -> Result<RequestId, SubmitError> {
        if password.is_some_and(|p| p.len() > crypto::MAX_PASSWORD_LEN) {
            return Err(crate::EncodeError::PasswordTooLong.into());
        }
        // Header, Message-Authenticator, hidden password.
        let overhead =
            HEADER_LEN + 18 + password.map_or(0, |p| 2 + p.len().div_ceil(16).max(1) * 16);
        if overhead + attrs.len() > MAX_PACKET_LEN {
            return Err(crate::EncodeError::PacketTooLong.into());
        }
        self.submit(
            Kind::Access,
            attrs,
            password.map(<[u8]>::to_vec),
            None,
            now_ms,
        )
    }

    /// Submit an Accounting-Request (attributes from
    /// [`crate::acct::Record::encode`]). With `supersede`, a pending request
    /// submitted with the same key is replaced (use it for interims).
    pub fn accounting(
        &mut self,
        attrs: AttrList,
        supersede: Option<u64>,
        now_ms: u64,
    ) -> Result<RequestId, SubmitError> {
        self.accounting_at(attrs, supersede, now_ms, now_ms)
    }

    /// [`Client::accounting`] of an event that happened at `event_ms`
    /// (held back by the caller): Acct-Delay-Time counts from it (RFC 2866
    /// §5.2), so the server dates the session right.
    pub fn accounting_at(
        &mut self,
        attrs: AttrList,
        supersede: Option<u64>,
        event_ms: u64,
        now_ms: u64,
    ) -> Result<RequestId, SubmitError> {
        // Header, Acct-Delay-Time.
        if HEADER_LEN + 6 + attrs.len() > MAX_PACKET_LEN {
            return Err(crate::EncodeError::PacketTooLong.into());
        }
        if let Some(old) = supersede.and_then(|k| self.supersede.get(&k).copied()) {
            self.finish(old, Some(Failure::Superseded));
        }
        let id = self.submit_at(
            Kind::Accounting,
            attrs,
            None,
            supersede,
            event_ms.min(now_ms),
            now_ms,
        );
        self.flush_drains(now_ms);
        let id = id?;
        if let Some(k) = supersede {
            self.supersede.insert(k, id);
        }
        Ok(id)
    }

    pub fn cancel(&mut self, request: RequestId) {
        self.finish(request, Some(Failure::Cancelled));
        self.flush_drains(self.last_now_ms);
    }

    fn flush_drains(&mut self, now_ms: u64) {
        self.last_now_ms = self.last_now_ms.max(now_ms);
        while let Some(s) = self.pending_drain.pop() {
            self.drain_queue(s, now_ms);
        }
    }

    fn service_of(kind: Kind) -> Service {
        match kind {
            Kind::Accounting => Service::Acct,
            Kind::Access | Kind::Status => Service::Auth,
        }
    }

    fn submit(
        &mut self,
        kind: Kind,
        attrs: AttrList,
        password: Option<Vec<u8>>,
        supersede: Option<u64>,
        now_ms: u64,
    ) -> Result<RequestId, SubmitError> {
        self.submit_at(kind, attrs, password, supersede, now_ms, now_ms)
    }

    fn submit_at(
        &mut self,
        kind: Kind,
        attrs: AttrList,
        password: Option<Vec<u8>>,
        supersede: Option<u64>,
        created_ms: u64,
        now_ms: u64,
    ) -> Result<RequestId, SubmitError> {
        self.last_now_ms = self.last_now_ms.max(now_ms);
        let service = Self::service_of(kind);
        let server = self
            .pick_server(service, 0, now_ms)
            .ok_or(SubmitError::NoServer)?;
        if self.pending >= self.cfg.max_pending {
            return Err(SubmitError::Busy);
        }
        let id = self.alloc_slot(Pending {
            generation: 0,
            kind,
            attrs,
            password,
            supersede,
            created_ms,
            server,
            tried: 1 << server,
            flight: None,
            seq: 0,
        });
        self.pending += 1;
        if let Some(s) = self.servers.get_mut(server) {
            s.stats.requests += 1;
        }
        self.dispatch(id, now_ms);
        Ok(id)
    }

    fn alloc_slot(&mut self, mut p: Pending) -> RequestId {
        let gen_ = self.next_gen;
        self.next_gen = self.next_gen.wrapping_add(1).max(1);
        p.generation = gen_;
        let slot = match self.free_slots.pop() {
            Some(s) => {
                if let Some(e) = self.slots.get_mut(s as usize) {
                    *e = Some(p);
                }
                s
            }
            None => {
                self.slots.push(Some(p));
                (self.slots.len() - 1) as u32
            }
        };
        RequestId::new(slot, gen_)
    }

    fn get(&self, r: RequestId) -> Option<&Pending> {
        self.slots
            .get(r.slot() as usize)?
            .as_ref()
            .filter(|p| p.generation == r.generation())
    }

    fn get_mut(&mut self, r: RequestId) -> Option<&mut Pending> {
        self.slots
            .get_mut(r.slot() as usize)?
            .as_mut()
            .filter(|p| p.generation == r.generation())
    }

    /// First live server of the service in configuration order, skipping
    /// `tried`; when all untried ones are dead, the dead one that comes back
    /// soonest.
    fn pick_server(&self, service: Service, tried: u64, now_ms: u64) -> Option<usize> {
        let candidates = || {
            self.servers
                .iter()
                .enumerate()
                .filter(move |(i, s)| s.cfg.service == service && tried & (1 << i) == 0)
        };
        candidates()
            .find(|(_, s)| s.alive || (!s.cfg.status_server && s.dead_until_ms <= now_ms))
            .or_else(|| candidates().min_by_key(|(_, s)| s.dead_until_ms))
            .map(|(i, _)| i)
    }

    /// Give the request an identifier on its server and queue its first
    /// transmission there; or put it in the server's queue.
    fn dispatch(&mut self, r: RequestId, now_ms: u64) {
        let Some(server) = self.get(r).map(|p| p.server) else {
            return;
        };
        let max_sockets = usize::from(self.cfg.max_sockets.max(1));
        let Some(s) = self.servers.get_mut(server) else {
            return;
        };
        let mut found = None;
        for (i, t) in s.sockets.iter_mut().enumerate() {
            if let Some(id) = t.alloc(r.slot()) {
                found = Some((i as u16, id));
                break;
            }
        }
        if found.is_none() && s.sockets.len() < max_sockets {
            let mut t = IdTable::new();
            let id = t.alloc(r.slot());
            s.sockets.push(t);
            found = id.map(|id| ((s.sockets.len() - 1) as u16, id));
        }
        let Some((socket, id)) = found else {
            s.queue.push_back((r.slot(), r.generation()));
            return;
        };
        s.stats.in_flight += 1;
        self.encode(r, socket, id, now_ms);
    }

    fn next_authenticator(&mut self) -> [u8; 16] {
        self.counter += 1;
        crypto::md5(&[&self.seed, &self.counter.to_le_bytes()])
    }

    /// Uniform in [-0.1, +0.1] × v (RFC 5080 §2.2.1 RAND).
    fn jitter(&mut self, v: u64) -> i64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        let span = v / 5;
        if span == 0 {
            return 0;
        }
        (self.rng % (span + 1)) as i64 - (span / 2) as i64
    }

    fn encode(&mut self, r: RequestId, socket: u16, id: u8, now_ms: u64) {
        let authenticator = self.next_authenticator();
        let Some(p) = self.get(r) else {
            return;
        };
        let Some(server) = self.servers.get(p.server) else {
            return;
        };
        let secret = &server.cfg.secret;
        let code = match p.kind {
            Kind::Access => Code::AccessRequest,
            Kind::Accounting => Code::AccountingRequest,
            Kind::Status => Code::StatusServer,
        };
        let mut b = Builder::with_authenticator(code, id, authenticator);
        let mut ok = true;
        if code != Code::AccountingRequest {
            ok &= b.message_authenticator().is_ok();
        }
        if let Some(pw) = &p.password {
            ok &= crypto::hide_user_password(pw, secret, &authenticator)
                .ok()
                .is_some_and(|h| b.push(attr::USER_PASSWORD, &h).is_ok());
        }
        ok &= b.extend(&p.attrs).is_ok();
        if p.kind == Kind::Accounting {
            let delay = now_ms.saturating_sub(p.created_ms) / 1000;
            ok &= b
                .push_u32(
                    attr::ACCT_DELAY_TIME,
                    u32::try_from(delay).unwrap_or(u32::MAX),
                )
                .is_ok();
        }
        // Sizes were checked at submission; a failure here means a bug,
        // reported as a timeout rather than a panic.
        let wire = crypto::sign_request(b, secret);
        // Accounting-Request authenticators are computed over the packet
        // (RFC 2866 §3): the reply is checked against that one.
        let mut authenticator = authenticator;
        if let Some(a) = wire.get(4..HEADER_LEN) {
            authenticator.copy_from_slice(a);
        }
        let (irt, learnt) = (server.cfg.retry.irt_ms, server.first_rt());
        let server_idx = p.server;
        if !ok {
            // The identifier is not attached to a flight yet: free it here.
            if let Some(s) = self.servers.get_mut(server_idx) {
                if let Some(t) = s.sockets.get_mut(usize::from(socket)) {
                    t.release(id, r.slot());
                }
                s.stats.in_flight = s.stats.in_flight.saturating_sub(1);
            }
            self.pending_drain.push(server_idx);
            self.finish(r, Some(Failure::Timeout));
            return;
        }
        // RFC 5080 §2.2.1's ±10 % on the IRT; never below what the server
        // is known to take.
        let rt = irt.saturating_add_signed(self.jitter(irt)).max(learnt);
        if let Some(p) = self.get_mut(r) {
            p.flight = Some(Flight {
                socket,
                id,
                authenticator,
                wire,
                tx: 0,
                first_tx_ms: now_ms,
                last_tx_ms: now_ms,
                rt_ms: rt,
            });
        }
        self.schedule_tx(r, now_ms);
    }

    /// Queue a (re)transmission and arm its timer.
    fn schedule_tx(&mut self, r: RequestId, now_ms: u64) {
        let Some(p) = self.get_mut(r) else {
            return;
        };
        let Some(f) = p.flight.as_mut() else {
            return;
        };
        f.tx += 1;
        f.last_tx_ms = now_ms;
        p.seq = p.seq.wrapping_add(1);
        let seq = p.seq;
        let deadline = now_ms.saturating_add(f.rt_ms);
        self.timers.push(Reverse((deadline, r.slot(), seq)));
        self.transmits.push_back((r.slot(), seq));
    }

    /// The next datagram, written into `buf`.
    pub fn poll_transmit(&mut self, buf: &mut Vec<u8>) -> Option<Transmit> {
        while let Some((slot, seq)) = self.transmits.pop_front() {
            let Some(Some(p)) = self.slots.get(slot as usize) else {
                continue;
            };
            if p.seq != seq {
                continue;
            }
            let Some(f) = p.flight.as_ref() else {
                continue;
            };
            let Some(s) = self.servers.get(p.server) else {
                continue;
            };
            buf.clear();
            buf.extend_from_slice(&f.wire);
            return Some(Transmit {
                from: SocketKey {
                    server: p.server,
                    socket: f.socket,
                },
                dest: s.cfg.addr,
                request: RequestId::new(slot, p.generation),
                identifier: f.id,
                retransmission: f.tx > 1,
            });
        }
        None
    }

    /// Earliest time [`Client::handle_timeout`] has work.
    pub fn poll_timeout(&self) -> Option<u64> {
        let req = self.timers.peek().map(|Reverse((t, _, _))| *t);
        let srv = self
            .servers
            .iter()
            .filter_map(|s| {
                if s.alive {
                    None
                } else if s.cfg.status_server {
                    s.next_probe_ms.filter(|_| !s.probing)
                } else {
                    Some(s.dead_until_ms)
                }
            })
            .min();
        match (req, srv) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    pub fn handle_timeout(&mut self, now_ms: u64) {
        while let Some(Reverse((t, slot, seq))) = self.timers.peek().copied() {
            if t > now_ms {
                break;
            }
            self.timers.pop();
            let Some(Some(p)) = self.slots.get(slot as usize) else {
                continue;
            };
            if p.seq != seq {
                continue;
            }
            let r = RequestId::new(slot, p.generation);
            self.expire(r, now_ms);
        }
        self.servers_tick(now_ms);
        self.flush_drains(now_ms);
    }

    fn servers_tick(&mut self, now_ms: u64) {
        let mut probes = Vec::new();
        for (i, s) in self.servers.iter_mut().enumerate() {
            if s.alive {
                continue;
            }
            if s.cfg.status_server {
                if !s.probing && s.next_probe_ms.is_some_and(|t| t <= now_ms) {
                    s.probing = true;
                    probes.push(i);
                }
            } else if s.dead_until_ms <= now_ms {
                // Zombie period over: try it again (RouterOS and Cisco
                // `deadtime` behave the same).
                s.alive = true;
                s.failures = 0;
                self.events.push_back(Event::ServerUp { server: i });
            }
        }
        for i in probes {
            self.probe(i, now_ms);
        }
    }

    fn probe(&mut self, server: usize, now_ms: u64) {
        let mut attrs = AttrList::new();
        let name = self.cfg.nas_identifier.as_bytes();
        let name = name.get(..name.len().min(253)).unwrap_or(&[]);
        if attrs.push(attr::NAS_IDENTIFIER, name).is_err() {
            return;
        }
        let r = self.alloc_slot(Pending {
            generation: 0,
            kind: Kind::Status,
            attrs,
            password: None,
            supersede: None,
            created_ms: now_ms,
            server,
            tried: u64::MAX,
            flight: None,
            seq: 0,
        });
        self.pending += 1;
        self.dispatch(r, now_ms);
    }

    /// The retransmission timer fired.
    fn expire(&mut self, r: RequestId, now_ms: u64) {
        let Some(p) = self.get(r) else {
            return;
        };
        let Some(f) = p.flight.as_ref() else {
            return;
        };
        let Some(s) = self.servers.get(p.server) else {
            return;
        };
        let (retry, server, prev, tx, first) =
            (s.cfg.retry, p.server, f.rt_ms, f.tx, f.first_tx_ms);
        let is_probe = p.kind == Kind::Status;
        let mrc_ok = retry.mrc == 0 || tx < retry.mrc;
        let elapsed = now_ms.saturating_sub(first);
        let mrd_ok = retry.mrd_ms == 0 || elapsed < retry.mrd_ms;
        if !(mrc_ok && mrd_ok) || is_probe {
            self.server_failed(r, now_ms);
            return;
        }
        // RFC 5080 §2.2.1: RT = 2·RTprev + RAND·RTprev, capped by
        // MRT + RAND·MRT; never past MRD.
        let mut rt = prev
            .saturating_mul(2)
            .saturating_add_signed(self.jitter(prev));
        if retry.mrt_ms > 0 && rt > retry.mrt_ms {
            rt = retry
                .mrt_ms
                .saturating_add_signed(self.jitter(retry.mrt_ms));
        }
        if retry.mrd_ms > 0 {
            rt = rt.min(retry.mrd_ms.saturating_sub(elapsed)).max(1);
        }
        if let Some(f) = self.get_mut(r).and_then(|p| p.flight.as_mut()) {
            f.rt_ms = rt;
        }
        if let Some(s) = self.servers.get_mut(server) {
            s.stats.resends += 1;
        }
        self.schedule_tx(r, now_ms);
    }

    /// MRC/MRD ran out on the current server: count it, maybe declare the
    /// server dead, and fail over.
    fn server_failed(&mut self, r: RequestId, now_ms: u64) {
        let Some(p) = self.get(r) else {
            return;
        };
        let (server, kind, tried, created) = (p.server, p.kind, p.tried, p.created_ms);
        self.release_id(r);
        let (dead_after, dead_time, probe_iv) = (
            self.cfg.dead_after.max(1),
            self.cfg.dead_time_ms,
            self.cfg.probe_interval_ms,
        );
        if let Some(s) = self.servers.get_mut(server) {
            s.stats.timeouts += 1;
            if kind == Kind::Status {
                s.probing = false;
                s.next_probe_ms = Some(now_ms + probe_iv);
            } else {
                s.failures += 1;
                if s.alive && s.failures >= dead_after {
                    s.alive = false;
                    s.dead_until_ms = now_ms + dead_time;
                    s.next_probe_ms = Some(now_ms + probe_iv.min(dead_time));
                    self.events.push_back(Event::ServerDown { server });
                }
            }
        }
        if kind == Kind::Status {
            self.finish(r, None);
            return;
        }
        let service = Self::service_of(kind);
        let next = match self.pick_server(service, tried, now_ms) {
            Some(n) => Some((n, tried | 1 << n)),
            None if kind == Kind::Accounting
                && (self.cfg.accounting_max_age_ms == 0
                    || now_ms.saturating_sub(created) < self.cfg.accounting_max_age_ms) =>
            {
                // A new round over every accounting server.
                self.pick_server(service, 0, now_ms).map(|n| (n, 1 << n))
            }
            None => None,
        };
        let Some((n, tried)) = next else {
            self.finish(r, Some(Failure::Timeout));
            return;
        };
        if let Some(p) = self.get_mut(r) {
            p.server = n;
            p.tried = tried;
        }
        if let Some(s) = self.servers.get_mut(n) {
            s.stats.requests += 1;
        }
        self.dispatch(r, now_ms);
    }

    /// Free the identifier and let a queued request of the same server
    /// take it.
    fn release_id(&mut self, r: RequestId) {
        let slot = r.slot();
        let Some(p) = self.get_mut(r) else {
            return;
        };
        let server = p.server;
        let Some(f) = p.flight.take() else {
            // Still queued: drop it from the queue lazily (dispatch skips
            // entries whose request is gone or already flying).
            return;
        };
        p.seq = p.seq.wrapping_add(1);
        if let Some(s) = self.servers.get_mut(server) {
            if let Some(t) = s.sockets.get_mut(usize::from(f.socket)) {
                t.release(f.id, slot);
            }
            s.stats.in_flight = s.stats.in_flight.saturating_sub(1);
        }
        self.pending_drain.push(server);
    }

    fn drain_queue(&mut self, server: usize, now_ms: u64) {
        loop {
            let Some(s) = self.servers.get_mut(server) else {
                return;
            };
            if !s.sockets.iter().any(|t| t.free > 0)
                && s.sockets.len() >= usize::from(self.cfg.max_sockets.max(1))
            {
                return;
            }
            let Some((slot, gen_)) = s.queue.pop_front() else {
                return;
            };
            let r = RequestId::new(slot, gen_);
            match self.get(r) {
                Some(p) if p.flight.is_none() && p.server == server => self.dispatch(r, now_ms),
                _ => continue,
            }
        }
    }

    /// Remove a request; `Some(reason)` emits [`Event::Failed`].
    fn finish(&mut self, r: RequestId, reason: Option<Failure>) {
        if self.get(r).is_none() {
            return;
        }
        self.release_id(r);
        if let Some(e) = self.slots.get_mut(r.slot() as usize)
            && let Some(p) = e.take()
            && let Some(k) = p.supersede
            && self.supersede.get(&k) == Some(&r)
        {
            self.supersede.remove(&k);
        }
        self.free_slots.push(r.slot());
        self.pending = self.pending.saturating_sub(1);
        if let Some(reason) = reason {
            self.events.push_back(Event::Failed { request: r, reason });
        }
    }

    /// A datagram arrived on `local` from `from`.
    pub fn handle_input(
        &mut self,
        local: SocketKey,
        from: SocketAddr,
        data: &[u8],
        now_ms: u64,
    ) -> Result<(), Discard> {
        let res = self.input(local, from, data, now_ms);
        if let Err(d) = res
            && let Some(s) = self.servers.get_mut(local.server)
        {
            match d {
                Discard::Unsolicited | Discard::UnknownSocket | Discard::WrongSource => {
                    s.stats.unsolicited += 1
                }
                _ => s.stats.bad_replies += 1,
            }
        }
        self.flush_drains(now_ms);
        res
    }

    fn input(
        &mut self,
        local: SocketKey,
        from: SocketAddr,
        data: &[u8],
        now_ms: u64,
    ) -> Result<(), Discard> {
        let s = self
            .servers
            .get(local.server)
            .ok_or(Discard::UnknownSocket)?;
        if from != s.cfg.addr {
            return Err(Discard::WrongSource);
        }
        let table = s
            .sockets
            .get(usize::from(local.socket))
            .ok_or(Discard::UnknownSocket)?;
        let p = Packet::parse(data).map_err(|_| Discard::Malformed)?;
        let slot = table.owner(p.identifier()).ok_or(Discard::Unsolicited)?;
        let Some(Some(pend)) = self.slots.get(slot as usize) else {
            return Err(Discard::Unsolicited);
        };
        let r = RequestId::new(slot, pend.generation);
        let f = pend.flight.as_ref().ok_or(Discard::Unsolicited)?;
        if pend.server != local.server || f.socket != local.socket {
            return Err(Discard::Unsolicited);
        }
        let expected = match (pend.kind, s.cfg.service) {
            (Kind::Access, _) => matches!(
                p.code(),
                Code::AccessAccept | Code::AccessReject | Code::AccessChallenge
            ),
            (Kind::Accounting, _) => p.code() == Code::AccountingResponse,
            // RFC 5997 §4.1: either code answers a Status-Server.
            (Kind::Status, _) => matches!(p.code(), Code::AccessAccept | Code::AccountingResponse),
        };
        if !expected {
            return Err(Discard::WrongCode);
        }
        let secret = &s.cfg.secret;
        if !crypto::verify_response(&p, &f.authenticator, secret) {
            return Err(Discard::BadAuthenticator);
        }
        // Status-Server answers carry no Message-Authenticator in RFC 5997
        // §6; they grant nothing, so the Response Authenticator suffices.
        let needs_ma = self.cfg.require_message_authenticator
            && pend.kind == Kind::Access
            && matches!(
                p.code(),
                Code::AccessAccept | Code::AccessReject | Code::AccessChallenge
            );
        match crypto::check_message_authenticator(&p, &f.authenticator, secret) {
            MaCheck::Invalid => return Err(Discard::BadMessageAuthenticator),
            MaCheck::Absent if needs_ma => return Err(Discard::BadMessageAuthenticator),
            _ => {}
        }
        let rtt = now_ms.saturating_sub(f.last_tx_ms);
        let once = f.tx == 1;
        let (kind, authenticator) = (pend.kind, f.authenticator);
        let server = local.server;
        if let Some(s) = self.servers.get_mut(server) {
            s.failures = 0;
            s.stats.last_rtt_ms = rtt;
            if once && kind != Kind::Status {
                s.sample(rtt);
            }
            match p.code() {
                Code::AccessAccept if kind == Kind::Access => s.stats.accepts += 1,
                Code::AccessReject => s.stats.rejects += 1,
                Code::AccessChallenge => s.stats.challenges += 1,
                Code::AccountingResponse => s.stats.acct_responses += 1,
                _ => {}
            }
            if kind == Kind::Status {
                s.probing = false;
                s.next_probe_ms = None;
            }
            if !s.alive {
                s.alive = true;
                self.events.push_back(Event::ServerUp { server });
            }
        }
        let code = p.code();
        let packet = p.as_bytes().to_vec();
        if kind != Kind::Status {
            self.events.push_back(Event::Response {
                request: r,
                server,
                code,
                packet,
                request_authenticator: authenticator,
                rtt_ms: rtt,
            });
        }
        self.finish(r, None);
        Ok(())
    }

    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Internal consistency (tests and the load simulation): every owned
    /// identifier points at a live request flying on that socket, and every
    /// flying request owns its identifier.
    #[doc(hidden)]
    pub fn check_invariants(&self) -> Result<(), String> {
        let mut flying = 0usize;
        for (si, s) in self.servers.iter().enumerate() {
            for (k, t) in s.sockets.iter().enumerate() {
                let owned = t.owner.iter().filter(|&&o| o != FREE).count();
                if owned + usize::from(t.free) != 256 {
                    return Err(format!(
                        "server {si} socket {k}: free count {} vs {owned} owned",
                        t.free
                    ));
                }
                for (id, &o) in t.owner.iter().enumerate() {
                    if o == FREE {
                        continue;
                    }
                    let Some(Some(p)) = self.slots.get(o as usize) else {
                        return Err(format!("server {si} socket {k} id {id}: owner {o} is gone"));
                    };
                    match &p.flight {
                        Some(f)
                            if p.server == si
                                && usize::from(f.socket) == k
                                && usize::from(f.id) == id => {}
                        _ => {
                            return Err(format!(
                                "server {si} socket {k} id {id}: owner {o} flies elsewhere"
                            ));
                        }
                    }
                    flying += 1;
                }
            }
        }
        let with_flight = self
            .slots
            .iter()
            .flatten()
            .filter(|p| p.flight.is_some())
            .count();
        if with_flight != flying {
            return Err(format!(
                "{with_flight} requests fly but {flying} identifiers are owned"
            ));
        }
        let live = self.slots.iter().flatten().count();
        if live != self.pending {
            return Err(format!("{live} live slots, pending says {}", self.pending));
        }
        Ok(())
    }
}

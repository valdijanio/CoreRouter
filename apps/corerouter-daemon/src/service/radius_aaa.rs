//! The RADIUS AAA driver (G4.3j): one thread that owns the
//! `proto-radius` clients and the CoA/DM server, moves their bytes over UDP
//! and keeps the time. Self-contained (no `super::`): the `radius` service
//! runs it under the supervisor, and the benchmark (`benches/radius_aaa.rs`)
//! includes this file as it is.
//!
//! - **Lanes.** One `proto_radius::client::Client` per AAA service in use
//!   (ppp, login, dhcp…), with the `/radius` entries of that service in
//!   failover order: authentication entries first in list order, then
//!   accounting with `accounting-backup` entries after the others. The
//!   client hands out 256 identifiers per socket and asks for another
//!   socket under load (up to 16 per server); each socket here is a
//!   `UdpSocket` bound to the entry's `src-address`, with a reader thread
//!   that posts datagrams to the driver's channel.
//! - **Reload.** A changed config builds new lanes; the old ones keep
//!   running until their pending requests end (an accounting Stop is never
//!   dropped by a config change), then their counters join the totals.
//! - **API.** [`Aaa`] implements the engine's `AaaBackend`: requests are
//!   queued on the channel and answered through callbacks run on this
//!   thread. Nothing here locks the session; log lines go to a queue the
//!   service drains ([`Aaa::take_logs`]).
//! - **CoA/DM.** `/radius incoming` listens when `accept=yes`. Sources are
//!   the enabled `/radius` entries (each with its secret); anything else
//!   is dropped silently (RFC 5176 §5: no reply to an unknown client).
//!   Checked requests go to the registered session owners in order; none
//!   takes it: NAK with Error-Cause 503 (Session Context Not Found).

use std::cmp::Reverse;
use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, BinaryHeap, HashMap, VecDeque};
use std::hash::{BuildHasher, Hasher};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use corerouter_engine::radius::{AaaBackend, AcctSource, AuthDone, SessionOwner};
use corerouter_model::ItemId;
use corerouter_model::ppp::PppAaa;
use corerouter_model::radius::{
    AaaService, AcctRequest, AcctStatus, Attribute, AuthOutcome, AuthReply, AuthRequest, CoaKind,
    CoaOutcome, CoaRequest, CoaSelector, Credentials, IncomingMonitor, RadiusIncoming,
    RadiusServer, RadiusStatus, RequireMessageAuth, ServerMonitor, ServerState,
};
use corerouter_proto_radius::acct::{self, Counters, InterimSchedule, Record, StatusType};
use corerouter_proto_radius::client::{
    Client, ClientConfig, Event, Failure, RequestId, Retry, ServerConfig, ServerStats, Service,
    SocketKey, SubmitError,
};
use corerouter_proto_radius::dict::{AttrId, DataType, Decoded, Dictionary, Encryption, Value};
use corerouter_proto_radius::dynauth::{
    DynAuthClient, DynAuthConfig, DynAuthRequest, DynAuthServer, ErrorCause, Incoming, Outcome,
    RequestKind,
};
use corerouter_proto_radius::mschap::{self, VENDOR_MICROSOFT};
use corerouter_proto_radius::packet::{AttrList, Code, Packet, PushAttr, VendorSpecific, attr};

/// Longest wait of the driver loop without looking at its clients.
const MAX_WAIT: Duration = Duration::from_millis(200);
/// Reader threads look at their stop flag this often.
const READ_TIMEOUT: Duration = Duration::from_millis(200);
/// Status is copied for `radius.monitor` at most this often.
const STATUS_EVERY: Duration = Duration::from_millis(100);
/// Log lines kept until the service drains them.
const MAX_LOGS: usize = 1000;
/// Messages handled before the clients get a turn (fairness under load).
const BURST: usize = 4096;
/// Requests waiting in the channel: a caller gets "busy" past this.
const MAX_QUEUED: usize = 200_000;
/// Socket receive buffer asked for (bytes).
const RECV_BUFFER: usize = 4 << 20;
/// Interims scheduled at most (sessions with a counter source).
const MAX_INTERIMS: usize = 1_000_000;

/// What the driver runs from: the running `/radius`, `/ppp aaa` and the
/// router's name.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AaaConfig {
    pub servers: Vec<RadiusServer>,
    pub incoming: RadiusIncoming,
    pub ppp: PppAaa,
    /// NAS-Identifier (RouterOS sends the identity).
    pub nas_identifier: String,
}

/// A log line for the router's log (topic `radius`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    /// `info`, `warning`, `error` or `debug`.
    pub level: &'static str,
    pub message: String,
}

enum Msg {
    Auth(Box<AuthRequest>, AuthDone),
    Acct(Box<AcctRequest>, Option<Arc<dyn AcctSource>>),
    Datagram {
        lane: u64,
        key: SocketKey,
        from: SocketAddr,
        data: Vec<u8>,
    },
    DynAuth {
        from: SocketAddr,
        data: Vec<u8>,
    },
    Reload(Box<AaaConfig>),
    Stop,
}

struct Shared {
    status: Mutex<RadiusStatus>,
    owners: Mutex<Vec<Arc<dyn SessionOwner>>>,
    logs: Mutex<VecDeque<LogLine>>,
    queued: std::sync::atomic::AtomicUsize,
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The handle callers hold (cheap to clone). Implements the engine's
/// `AaaBackend`.
#[derive(Clone)]
pub struct Aaa {
    tx: Sender<Msg>,
    shared: Arc<Shared>,
}

impl Aaa {
    /// Lines logged since the last call, oldest first.
    pub fn take_logs(&self) -> Vec<LogLine> {
        guard(&self.shared.logs).drain(..).collect()
    }

    /// Run with `cfg` (the driver reloads only what changed).
    pub fn reload(&self, cfg: AaaConfig) {
        let _ = self.tx.send(Msg::Reload(Box::new(cfg)));
    }

    pub fn stop(&self) {
        let _ = self.tx.send(Msg::Stop);
    }

    fn post(&self, m: Msg) -> bool {
        if self.shared.queued.load(Ordering::Relaxed) >= MAX_QUEUED {
            return false;
        }
        self.shared.queued.fetch_add(1, Ordering::Relaxed);
        if self.tx.send(m).is_err() {
            self.shared.queued.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        true
    }
}

impl AaaBackend for Aaa {
    fn authenticate(&self, req: AuthRequest, done: AuthDone) {
        // The callback comes back inside the message if it cannot be
        // posted; answer it here then.
        let slot: Arc<Mutex<Option<AuthDone>>> = Arc::new(Mutex::new(Some(done)));
        let inner = slot.clone();
        let wrapped: AuthDone = Box::new(move |r| {
            if let Some(d) = guard(&inner).take() {
                d(r);
            }
        });
        if !self.post(Msg::Auth(Box::new(req), wrapped))
            && let Some(d) = guard(&slot).take()
        {
            d(AuthReply::failed(
                AuthOutcome::Error,
                "the radius service is busy or stopped",
            ));
        }
    }

    fn account(&self, req: AcctRequest, source: Option<Arc<dyn AcctSource>>) -> Result<(), String> {
        if self.post(Msg::Acct(Box::new(req), source)) {
            Ok(())
        } else {
            Err("the radius service is busy or stopped".into())
        }
    }

    fn register_owner(&self, owner: Arc<dyn SessionOwner>) {
        guard(&self.shared.owners).push(owner);
    }

    fn status(&self) -> RadiusStatus {
        guard(&self.shared.status).clone()
    }
}

/// The driver's end of the channel, given to [`run`]. Kept in a mutex so a
/// restarted service picks the same channel up again (callers keep their
/// [`Aaa`]).
pub struct Inbox(Mutex<Receiver<Msg>>);

/// A handle and the inbox [`run`] reads.
pub fn channel() -> (Aaa, Arc<Inbox>) {
    let (tx, rx) = mpsc::channel();
    let shared = Arc::new(Shared {
        status: Mutex::new(RadiusStatus::default()),
        owners: Mutex::new(Vec::new()),
        logs: Mutex::new(VecDeque::new()),
        queued: std::sync::atomic::AtomicUsize::new(0),
    });
    (Aaa { tx, shared }, Arc::new(Inbox(Mutex::new(rx))))
}

/// Start the driver on its own thread; it ends on [`Aaa::stop`] (tests
/// and the benchmark; the service runs [`run`] under the supervisor).
#[allow(dead_code)]
pub fn spawn(cfg: AaaConfig) -> std::io::Result<(Aaa, thread::JoinHandle<()>)> {
    let (aaa, inbox) = channel();
    let me = aaa.clone();
    aaa.reload(cfg);
    let h = thread::Builder::new()
        .name("radius-aaa".into())
        .spawn(move || run(&me, &inbox, &|| false))?;
    Ok((aaa, h))
}

/// 32 bytes from the OS (every `RandomState` is seeded from it).
fn random_seed() -> [u8; 32] {
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        let mut h = RandomState::new().build_hasher();
        h.write_u64(0x5241_4449_5553);
        chunk.copy_from_slice(&h.finish().to_le_bytes());
    }
    out
}

fn now_unix() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u32::try_from(d.as_secs()).unwrap_or(u32::MAX))
        .unwrap_or(0)
}

/// A stable 64-bit key of a session id (interim supersede and jitter).
fn key_of(s: &str) -> u64 {
    // FNV-1a: stable across restarts, unlike `RandomState`.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

// ---- lanes ------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ServerRef {
    id: ItemId,
    service: Service,
}

/// Everything a lane is built from; equal specs keep the running lane.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LaneSpec {
    servers: Vec<ServerConfig>,
    refs: Vec<ServerRef>,
    /// Per client server: source address and VRF of its sockets.
    binds: Vec<(Option<IpAddr>, String)>,
    status_server: Vec<bool>,
    require_ma: bool,
    realm: String,
    called_id: String,
    nas_identifier: String,
}

enum Waiting {
    Auth { done: AuthDone, realm_user: String },
    Acct { session: String, status: AcctStatus },
}

struct Sock {
    socket: Arc<UdpSocket>,
    stop: Arc<AtomicBool>,
}

struct Lane {
    id: u64,
    service: AaaService,
    spec: LaneSpec,
    client: Client,
    sockets: HashMap<SocketKey, Sock>,
    waiting: HashMap<RequestId, Waiting>,
    /// Bind failures already logged (once per server).
    bind_failed: Vec<bool>,
}

impl Lane {
    fn new(id: u64, service: AaaService, spec: LaneSpec) -> Self {
        let cfg = ClientConfig {
            require_message_authenticator: spec.require_ma,
            nas_identifier: spec.nas_identifier.clone(),
            ..ClientConfig::default()
        };
        let mut servers = spec.servers.clone();
        for (s, probe) in servers.iter_mut().zip(&spec.status_server) {
            s.status_server = *probe;
        }
        let n = servers.len();
        Self {
            id,
            service,
            client: Client::new(cfg, servers, random_seed()),
            spec,
            sockets: HashMap::new(),
            waiting: HashMap::new(),
            bind_failed: vec![false; n],
        }
    }

    fn close(&mut self) {
        for s in self.sockets.values() {
            s.stop.store(true, Ordering::Relaxed);
        }
        self.sockets.clear();
    }
}

impl Drop for Lane {
    fn drop(&mut self) {
        self.close();
    }
}

/// The client servers of `service` from the config, in failover order.
fn lane_spec(cfg: &AaaConfig, service: AaaService) -> Option<LaneSpec> {
    let mine: Vec<&RadiusServer> = cfg.servers.iter().filter(|e| e.serves(service)).collect();
    let first = mine.first()?;
    let mut spec = LaneSpec {
        servers: Vec::new(),
        refs: Vec::new(),
        binds: Vec::new(),
        status_server: Vec::new(),
        // One old server that cannot sign (`no`) lowers the lane: its
        // replies would all be dropped otherwise. The ⓘ says so.
        require_ma: mine
            .iter()
            .all(|e| e.require_message_auth == RequireMessageAuth::YesForRequestResp),
        realm: first.realm.clone(),
        called_id: first.called_id.clone(),
        nas_identifier: cfg.nas_identifier.clone(),
    };
    let mut push = |e: &RadiusServer, svc: Service| {
        let (port, mut retry) = match svc {
            Service::Auth => (e.authentication_port, Retry::ACCESS),
            Service::Acct => (e.accounting_port, Retry::ACCOUNTING),
        };
        // RouterOS `timeout` is the first wait; backoff doubles it up to 4×
        // (accounting never waits less than RFC 5080's 2 s).
        retry.irt_ms = match svc {
            Service::Auth => u64::from(e.timeout),
            Service::Acct => u64::from(e.timeout).max(Retry::ACCOUNTING.irt_ms),
        };
        retry.mrt_ms = retry.mrt_ms.max(retry.irt_ms.saturating_mul(4));
        retry.mrd_ms = retry.mrd_ms.max(retry.irt_ms.saturating_mul(3));
        spec.servers.push(ServerConfig {
            addr: SocketAddr::new(e.address, port),
            secret: e.secret.as_bytes().to_vec(),
            service: svc,
            retry,
            status_server: false,
        });
        spec.refs.push(ServerRef {
            id: e.id,
            service: svc,
        });
        spec.binds.push((e.src_address, e.vrf.clone()));
        spec.status_server.push(e.status_server);
    };
    for e in &mine {
        push(e, Service::Auth);
    }
    for backup in [false, true] {
        for e in mine.iter().filter(|e| e.accounting_backup == backup) {
            push(e, Service::Acct);
        }
    }
    Some(spec)
}

// ---- encoding requests ------------------------------------------------------

fn service_type(s: AaaService) -> u32 {
    // RFC 2865 §5.6: Framed for PPP/IPoE, Login for the router's own login.
    match s {
        AaaService::Login => 1,
        _ => 2,
    }
}

/// `value` of attribute `name` as the dictionary types it.
fn encode_attr(dict: &Dictionary, l: &mut AttrList, a: &Attribute) -> Result<(), String> {
    let shown: String = a.name.chars().take(48).collect();
    let def = dict
        .by_name(&a.name)
        .ok_or_else(|| format!("unknown attribute '{shown}'"))?;
    if def.encrypt != Encryption::None {
        return Err(format!(
            "{shown}: encrypted attributes cannot be sent this way"
        ));
    }
    let bad = || format!("{shown}: bad value for its type");
    let mut v: Vec<u8> = match def.data {
        DataType::Text | DataType::String => a.value.as_bytes().to_vec(),
        DataType::Integer | DataType::Time => a
            .value
            .trim()
            .parse::<u32>()
            .map_err(|_| bad())?
            .to_be_bytes()
            .to_vec(),
        DataType::Integer64 => a
            .value
            .trim()
            .parse::<u64>()
            .map_err(|_| bad())?
            .to_be_bytes()
            .to_vec(),
        DataType::Ipv4Addr => a
            .value
            .trim()
            .parse::<Ipv4Addr>()
            .map_err(|_| bad())?
            .octets()
            .to_vec(),
        DataType::Ipv6Addr => a
            .value
            .trim()
            .parse::<Ipv6Addr>()
            .map_err(|_| bad())?
            .octets()
            .to_vec(),
        _ => return Err(format!("{shown}: this type cannot be sent this way")),
    };
    if let (true, Some(t)) = (def.tagged, a.tag) {
        v.insert(0, t);
    }
    let r = match def.id {
        AttrId::Std(t) => l.push(t, &v).map(|_| ()),
        AttrId::Vendor(vendor, t) => l.push_vsa(vendor, t, &v).map(|_| ()),
        AttrId::Ext(t, e) => l.push_extended(t, e, &v).map(|_| ()),
    };
    r.map_err(|e| format!("{shown}: {e}"))
}

fn nas_attrs(l: &mut AttrList, spec: &LaneSpec) -> Result<(), String> {
    if !spec.nas_identifier.is_empty() {
        l.push_text(attr::NAS_IDENTIFIER, &spec.nas_identifier)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// User-Name with the lane's realm when it has none (RouterOS `realm`).
fn realm_user(user: &str, realm: &str) -> String {
    if realm.is_empty() || user.contains('@') {
        user.to_owned()
    } else {
        format!("{user}@{realm}")
    }
}

fn auth_attrs(
    dict: &Dictionary,
    spec: &LaneSpec,
    r: &AuthRequest,
) -> Result<(AttrList, Option<Vec<u8>>, String), String> {
    let mut l = AttrList::new();
    let e = |e: corerouter_proto_radius::EncodeError| e.to_string();
    let user = realm_user(&r.user, &spec.realm);
    l.push_text(attr::USER_NAME, &user).map_err(e)?;
    l.push_u32(attr::SERVICE_TYPE, service_type(r.service))
        .map_err(e)?;
    if r.service == AaaService::Ppp {
        // RFC 2865 §5.7: PPP.
        l.push_u32(attr::FRAMED_PROTOCOL, 1).map_err(e)?;
    }
    nas_attrs(&mut l, spec)?;
    if let Some(p) = r.nas_port {
        l.push_u32(attr::NAS_PORT, p).map_err(e)?;
    }
    if let Some(p) = &r.nas_port_id {
        l.push_text(attr::NAS_PORT_ID, p).map_err(e)?;
    }
    if let Some(c) = &r.calling_station_id {
        l.push_text(attr::CALLING_STATION_ID, c).map_err(e)?;
    }
    match (&r.called_station_id, spec.called_id.is_empty()) {
        (Some(c), _) => {
            l.push_text(attr::CALLED_STATION_ID, c).map_err(e)?;
        }
        (None, false) => {
            l.push_text(attr::CALLED_STATION_ID, &spec.called_id)
                .map_err(e)?;
        }
        (None, true) => {}
    }
    let mut password = None;
    match &r.credentials {
        Credentials::Pap { password: p } => password = Some(p.as_bytes().to_vec()),
        Credentials::Chap {
            id,
            challenge,
            response,
        } => {
            // RFC 2865 §5.3: CHAP Ident, then the 16-byte response.
            if response.len() != 16 {
                return Err("CHAP response must be 16 bytes".into());
            }
            let mut v = vec![*id];
            v.extend_from_slice(response);
            l.push(attr::CHAP_PASSWORD, &v).map_err(e)?;
            l.push(attr::CHAP_CHALLENGE, challenge).map_err(e)?;
        }
        Credentials::MsChapV2 {
            ident,
            challenge,
            peer_challenge,
            nt_response,
        } => {
            // RFC 2548 §2.3.2 and §2.3.1.
            let (Ok(peer), Ok(nt)) = (
                <[u8; 16]>::try_from(peer_challenge.as_slice()),
                <[u8; 24]>::try_from(nt_response.as_slice()),
            ) else {
                return Err("MS-CHAPv2: peer challenge is 16 bytes, NT-Response 24".into());
            };
            let resp = mschap::Chap2Response {
                ident: *ident,
                flags: 0,
                peer_challenge: peer,
                nt_response: nt,
            };
            l.push_vsa(VENDOR_MICROSOFT, mschap::vsa::MS_CHAP_CHALLENGE, challenge)
                .map_err(e)?;
            l.push_vsa(
                VENDOR_MICROSOFT,
                mschap::vsa::MS_CHAP2_RESPONSE,
                &resp.encode(),
            )
            .map_err(e)?;
        }
        Credentials::None => {}
    }
    for a in r
        .attributes
        .iter()
        .take(corerouter_model::radius::MAX_EXTRA_ATTRS)
    {
        encode_attr(dict, &mut l, a)?;
    }
    Ok((l, password, user))
}

fn acct_attrs(dict: &Dictionary, spec: &LaneSpec, r: &AcctRequest) -> Result<AttrList, String> {
    let status = match r.status {
        AcctStatus::Start => StatusType::Start,
        AcctStatus::InterimUpdate => StatusType::InterimUpdate,
        AcctStatus::Stop => StatusType::Stop,
    };
    let mut rec = Record::new(status, r.session_id.clone());
    rec.authentic = Some(acct::Authentic::Radius);
    rec.counters = r.counters.map(|c| Counters {
        input_octets: c.input_octets,
        output_octets: c.output_octets,
        input_packets: c.input_packets,
        output_packets: c.output_packets,
        session_time: c.session_time,
    });
    rec.event_timestamp = Some(now_unix());
    let e = |e: corerouter_proto_radius::EncodeError| e.to_string();
    let mut l = rec.encode().map_err(e)?;
    if let (AcctStatus::Stop, Some(t)) = (r.status, r.terminate_cause) {
        l.push_u32(attr::ACCT_TERMINATE_CAUSE, t).map_err(e)?;
    }
    l.push_text(attr::USER_NAME, &realm_user(&r.user, &spec.realm))
        .map_err(e)?;
    l.push_u32(attr::SERVICE_TYPE, service_type(r.service))
        .map_err(e)?;
    nas_attrs(&mut l, spec)?;
    for a in r
        .attributes
        .iter()
        .take(corerouter_model::radius::MAX_EXTRA_ATTRS)
    {
        encode_attr(dict, &mut l, a)?;
    }
    Ok(l)
}

// ---- decoding replies -------------------------------------------------------

fn hex(v: &[u8]) -> String {
    let mut s = String::from("0x");
    for b in v.iter().take(64) {
        s.push_str(&format!("{b:02x}"));
    }
    if v.len() > 64 {
        s.push('…');
    }
    s
}

fn value_text(v: &Value<'_>) -> String {
    match v {
        Value::Text(t) => (*t).to_owned(),
        Value::Octets(o) => match std::str::from_utf8(o) {
            Ok(t) if !t.is_empty() && t.chars().all(|c| !c.is_control()) => t.to_owned(),
            _ => hex(o),
        },
        Value::Integer(n) => n.to_string(),
        Value::Integer64(n) => n.to_string(),
        Value::Ipv4(a) => a.to_string(),
        Value::Ipv6(a) => a.to_string(),
        Value::Ipv6Prefix(a, l) => format!("{a}/{l}"),
        Value::Ipv4Prefix(a, l) => format!("{a}/{l}"),
        Value::Ifid(b) => hex(b),
        Value::Time(t) => t.to_string(),
        Value::Invalid(b) => format!("(invalid) {}", hex(b)),
    }
}

fn attr_name(d: &Decoded<'_, '_>) -> String {
    match (d.def, d.id) {
        (Some(def), _) => def.name.to_string(),
        (None, AttrId::Std(t)) => format!("Attr-{t}"),
        (None, AttrId::Vendor(v, t)) => format!("Attr-26.{v}.{t}"),
        (None, AttrId::Ext(t, e)) => format!("Attr-{t}.{e}"),
    }
}

fn decoded(d: &Decoded<'_, '_>) -> Option<Attribute> {
    // Bookkeeping, not what the operator wants to read.
    if matches!(
        d.id,
        AttrId::Std(attr::MESSAGE_AUTHENTICATOR | attr::PROXY_STATE)
    ) {
        return None;
    }
    let value = match (d.def.map(|x| x.encrypt), &d.value) {
        (Some(Encryption::None) | None, v) => value_text(v),
        (Some(_), Value::Octets(o) | Value::Invalid(o)) => {
            format!("(encrypted, {} bytes)", o.len())
        }
        (Some(_), v) => value_text(v),
    };
    Some(Attribute {
        name: attr_name(d),
        value,
        tag: d.tag,
    })
}

fn decode_all(dict: &Dictionary, p: &Packet<'_>) -> Vec<Attribute> {
    dict.decode_packet(p).iter().filter_map(decoded).collect()
}

fn decode_list(dict: &Dictionary, l: &AttrList) -> Vec<Attribute> {
    let mut out = Vec::new();
    for a in l.iter() {
        if a.typ == attr::VENDOR_SPECIFIC {
            if let Some(vs) = VendorSpecific::parse(a.value) {
                for v in vs {
                    if let Some(x) = decoded(&dict.decode(AttrId::Vendor(v.vendor, v.typ), v.value))
                    {
                        out.push(x);
                    }
                }
            }
        } else if let Some(x) = decoded(&dict.decode(AttrId::Std(a.typ), a.value)) {
            out.push(x);
        }
    }
    out
}

// ---- interims ---------------------------------------------------------------

struct InterimEntry {
    req: AcctRequest,
    source: Arc<dyn AcctSource>,
    schedule: InterimSchedule,
    start_ms: u64,
    n: u64,
}

/// Interim-Updates of the sessions with a counter source, each on its own
/// jittered schedule (`acct::InterimSchedule`: a fixed offset per session
/// within `jitter` % of the interval, so 10 000 sessions that start in the
/// same second do not report in the same second forever).
#[derive(Default)]
pub struct Interims {
    heap: BinaryHeap<Reverse<(u64, u64)>>,
    entries: HashMap<u64, InterimEntry>,
    by_session: HashMap<String, u64>,
    next: u64,
}

#[allow(dead_code)]
impl Interims {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Schedule `req`'s session (a Start) every `interval_secs`.
    pub fn add(
        &mut self,
        req: AcctRequest,
        source: Arc<dyn AcctSource>,
        interval_secs: u32,
        jitter_pct: u8,
        now_ms: u64,
    ) -> Option<u64> {
        if self.entries.len() >= MAX_INTERIMS {
            return None;
        }
        self.remove(&req.session_id);
        let schedule = InterimSchedule::new(interval_secs, jitter_pct, key_of(&req.session_id));
        let due = schedule.due(now_ms, 1);
        self.next += 1;
        let k = self.next;
        self.by_session.insert(req.session_id.clone(), k);
        self.entries.insert(
            k,
            InterimEntry {
                req,
                source,
                schedule,
                start_ms: now_ms,
                n: 1,
            },
        );
        self.heap.push(Reverse((due, k)));
        Some(due)
    }

    pub fn remove(&mut self, session: &str) {
        if let Some(k) = self.by_session.remove(session) {
            self.entries.remove(&k);
        }
    }

    pub fn next_due(&self) -> Option<u64> {
        self.heap.peek().map(|Reverse((t, _))| *t)
    }

    /// The Interim-Updates due at `now_ms` (with fresh counters); each
    /// session is scheduled again. A source that answers `None` ends.
    pub fn due(&mut self, now_ms: u64) -> Vec<AcctRequest> {
        let mut out = Vec::new();
        while let Some(Reverse((t, k))) = self.heap.peek().copied() {
            if t > now_ms {
                break;
            }
            self.heap.pop();
            let Some(e) = self.entries.get_mut(&k) else {
                continue;
            };
            match e.source.counters() {
                Some(c) => {
                    let mut r = e.req.clone();
                    r.status = AcctStatus::InterimUpdate;
                    r.counters = Some(c);
                    out.push(r);
                    e.n += 1;
                    let next = e.schedule.due(e.start_ms, e.n).max(now_ms + 1);
                    self.heap.push(Reverse((next, k)));
                }
                None => {
                    let s = e.req.session_id.clone();
                    self.entries.remove(&k);
                    self.by_session.remove(&s);
                }
            }
        }
        out
    }
}

// ---- the driver -------------------------------------------------------------

struct Driver<'a> {
    aaa: &'a Aaa,
    t0: Instant,
    dict: Dictionary,
    cfg: AaaConfig,
    lanes: BTreeMap<AaaService, Lane>,
    retiring: Vec<Lane>,
    next_lane: u64,
    /// Counters of lanes gone, per entry.
    base: HashMap<ItemId, ServerStats>,
    interims: Interims,
    dynauth: Option<(DynAuth, DynAuthServer)>,
    dyn_stats_base: corerouter_proto_radius::dynauth::DynAuthStats,
    incoming_error: Option<String>,
    buf: Vec<u8>,
    last_status: Instant,
}

struct DynAuth {
    socket: Arc<UdpSocket>,
    stop: Arc<AtomicBool>,
    at: SocketAddr,
    cfg: (RadiusIncoming, Vec<(IpAddr, String)>),
}

impl Drop for DynAuth {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn reader(
    socket: Arc<UdpSocket>,
    stop: Arc<AtomicBool>,
    tx: Sender<Msg>,
    tag: impl Fn(SocketAddr, Vec<u8>) -> Msg + Send + 'static,
) -> std::io::Result<()> {
    socket.set_read_timeout(Some(READ_TIMEOUT))?;
    thread::Builder::new()
        .name("radius-rx".into())
        .stack_size(128 * 1024)
        .spawn(move || {
            let mut buf = vec![0u8; 4096];
            while !stop.load(Ordering::Relaxed) {
                match socket.recv_from(&mut buf) {
                    Ok((n, from)) => {
                        let data = buf.get(..n).unwrap_or_default().to_vec();
                        if tx.send(tag(from, data)).is_err() {
                            return;
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) => {}
                    Err(_) => thread::sleep(READ_TIMEOUT),
                }
            }
        })
        .map(|_| ())
}

/// A UDP socket from `src` (or any address of `family`), in `vrf`.
fn bind_udp(src: Option<IpAddr>, v4: bool, vrf: &str, port: u16) -> std::io::Result<UdpSocket> {
    let ip = src.unwrap_or(if v4 {
        IpAddr::V4(Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    });
    let addr = SocketAddr::new(ip, port);
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let s = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    if vrf != "main" {
        // SO_BINDTODEVICE on the VRF device (needs CAP_NET_RAW).
        #[cfg(target_os = "linux")]
        s.bind_device(Some(vrf.as_bytes()))?;
        #[cfg(not(target_os = "linux"))]
        return Err(std::io::Error::other("VRF sockets need Linux"));
    }
    if port != 0 {
        s.set_reuse_address(true)?;
    }
    // A burst of replies (thousands of logins after an outage) must not
    // overflow the default ~200 KiB buffer: the kernel caps this at
    // net.core.rmem_max (system.tuning raises it).
    let _ = s.set_recv_buffer_size(RECV_BUFFER);
    s.bind(&addr.into())?;
    Ok(s.into())
}

impl<'a> Driver<'a> {
    fn ms(&self) -> u64 {
        u64::try_from(self.t0.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn log(&self, level: &'static str, message: String) {
        let mut q = guard(&self.aaa.shared.logs);
        if q.len() >= MAX_LOGS {
            q.pop_front();
        }
        q.push_back(LogLine { level, message });
    }

    fn reload(&mut self, cfg: AaaConfig) {
        let mut seen = Vec::new();
        for service in AaaService::ALL {
            let spec = lane_spec(&cfg, service);
            let same = match (self.lanes.get(&service), &spec) {
                (Some(l), Some(s)) => l.spec == *s,
                (None, None) => true,
                _ => false,
            };
            if same {
                continue;
            }
            if let Some(old) = self.lanes.remove(&service) {
                self.retire(old);
            }
            if let Some(spec) = spec {
                self.next_lane += 1;
                let n = spec.refs.len();
                self.lanes
                    .insert(service, Lane::new(self.next_lane, service, spec));
                seen.push(format!("{} ({n} destinos)", service.as_str()));
            }
        }
        if !seen.is_empty() {
            self.log(
                "info",
                format!("RADIUS: servidores carregados para {}", seen.join(", ")),
            );
        }
        self.cfg = cfg;
        self.reload_incoming();
    }

    fn retire(&mut self, lane: Lane) {
        if lane.client.pending() == 0 {
            self.absorb(&lane);
        } else {
            self.retiring.push(lane);
        }
    }

    /// A lane's counters join the totals of its entries.
    fn absorb(&mut self, lane: &Lane) {
        for (i, r) in lane.spec.refs.iter().enumerate() {
            if let Some(st) = lane.client.stats(i) {
                let b = self.base.entry(r.id).or_default();
                add_stats(b, &st, false);
            }
        }
    }

    fn reload_incoming(&mut self) {
        let inc = &self.cfg.incoming;
        let clients: Vec<(IpAddr, String)> = {
            let mut v: Vec<(IpAddr, String)> = Vec::new();
            for e in self.cfg.servers.iter().filter(|e| !e.disabled) {
                if !v.iter().any(|(a, _)| *a == e.address) {
                    v.push((e.address, e.secret.clone()));
                }
            }
            v
        };
        let want = (inc.clone(), clients);
        if !inc.accept {
            if self.dynauth.take().is_some() {
                self.log(
                    "info",
                    "RADIUS: CoA/Disconnect desligado (incoming accept=no)".into(),
                );
            }
            self.incoming_error = None;
            return;
        }
        if let Some((d, srv)) = &mut self.dynauth {
            if d.cfg == want {
                return;
            }
            if d.cfg.0.port == inc.port && d.cfg.0.vrf == inc.vrf {
                // Same socket: new allow-list and rules.
                let st = srv.stats();
                add_dyn(&mut self.dyn_stats_base, &st);
                *srv = DynAuthServer::new(dyn_config(&want));
                d.cfg = want;
                return;
            }
        }
        if let Some((_, srv)) = self.dynauth.take() {
            add_dyn(&mut self.dyn_stats_base, &srv.stats());
        }
        let bound = bind_udp(None, false, &inc.vrf, inc.port)
            .or_else(|_| bind_udp(None, true, &inc.vrf, inc.port));
        match bound {
            Ok(sock) => {
                let socket = Arc::new(sock);
                let stop = Arc::new(AtomicBool::new(false));
                let at = socket
                    .local_addr()
                    .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], inc.port)));
                if let Err(e) = reader(
                    socket.clone(),
                    stop.clone(),
                    self.aaa.tx.clone(),
                    |from, data| Msg::DynAuth { from, data },
                ) {
                    self.incoming_error = Some(format!("thread: {e}"));
                    return;
                }
                self.log(
                    "info",
                    format!("RADIUS: aceitando CoA/Disconnect na porta UDP {}", inc.port),
                );
                self.incoming_error = None;
                let srv = DynAuthServer::new(dyn_config(&want));
                self.dynauth = Some((
                    DynAuth {
                        socket,
                        stop,
                        at,
                        cfg: want,
                    },
                    srv,
                ));
            }
            Err(e) => {
                let why = format!("não consegui abrir a porta UDP {}: {e}", inc.port);
                if self.incoming_error.as_deref() != Some(&why) {
                    self.log("error", format!("RADIUS incoming: {why}"));
                }
                self.incoming_error = Some(why);
            }
        }
    }

    fn lane_mut(&mut self, id: u64) -> Option<&mut Lane> {
        if let Some(l) = self.lanes.values_mut().find(|l| l.id == id) {
            return Some(l);
        }
        self.retiring.iter_mut().find(|l| l.id == id)
    }

    fn auth(&mut self, req: AuthRequest, done: AuthDone) {
        let now = self.ms();
        let service = req.service;
        let Some(lane) = self.lanes.get_mut(&service) else {
            done(AuthReply::failed(
                AuthOutcome::Error,
                format!("no enabled /radius entry has service={}", service.as_str()),
            ));
            return;
        };
        let (attrs, password, user) = match auth_attrs(&self.dict, &lane.spec, &req) {
            Ok(x) => x,
            Err(e) => {
                done(AuthReply::failed(AuthOutcome::Error, e));
                return;
            }
        };
        match lane.client.access(attrs, password.as_deref(), now) {
            Ok(id) => {
                lane.waiting.insert(
                    id,
                    Waiting::Auth {
                        done,
                        realm_user: user,
                    },
                );
            }
            Err(e) => done(AuthReply::failed(AuthOutcome::Error, submit_error(&e))),
        }
    }

    fn acct(&mut self, req: AcctRequest, source: Option<Arc<dyn AcctSource>>) {
        let now = self.ms();
        if req.service == AaaService::Ppp && !self.cfg.ppp.accounting {
            return;
        }
        match req.status {
            AcctStatus::Start => {
                let interval = req.interim_secs.unwrap_or(match req.service {
                    AaaService::Ppp => self.cfg.ppp.interim_update,
                    _ => 0,
                });
                if let (Some(src), true) = (source, interval > 0) {
                    let jitter = self.cfg.ppp.interim_jitter;
                    if self
                        .interims
                        .add(req.clone(), src, interval, jitter, now)
                        .is_none()
                    {
                        self.log(
                            "warning",
                            "RADIUS: limite de sessões com interim atingido".into(),
                        );
                    }
                }
            }
            AcctStatus::Stop => self.interims.remove(&req.session_id),
            AcctStatus::InterimUpdate => {}
        }
        self.send_acct(req, now);
    }

    fn send_acct(&mut self, req: AcctRequest, now: u64) {
        let Some(lane) = self.lanes.get_mut(&req.service) else {
            return;
        };
        let attrs = match acct_attrs(&self.dict, &lane.spec, &req) {
            Ok(a) => a,
            Err(e) => {
                let msg = format!(
                    "RADIUS: contabilização de {} não enviada: {e}",
                    req.session_id
                );
                self.log("warning", msg);
                return;
            }
        };
        // A newer interim of the same session replaces a pending one.
        let supersede = (req.status == AcctStatus::InterimUpdate).then(|| key_of(&req.session_id));
        match lane.client.accounting(attrs, supersede, now) {
            Ok(id) => {
                lane.waiting.insert(
                    id,
                    Waiting::Acct {
                        session: req.session_id,
                        status: req.status,
                    },
                );
            }
            Err(e) => {
                let msg = format!(
                    "RADIUS: contabilização de {} recusada: {}",
                    req.session_id,
                    submit_error(&e)
                );
                self.log("warning", msg);
            }
        }
    }

    fn datagram(&mut self, lane: u64, key: SocketKey, from: SocketAddr, data: &[u8]) {
        let now = self.ms();
        if let Some(l) = self.lane_mut(lane) {
            // Counted by the client (bad_replies, unsolicited).
            let _ = l.client.handle_input(key, from, data, now);
        }
    }

    fn dyn_auth(&mut self, from: SocketAddr, data: &[u8]) {
        let now = self.ms();
        let unix = now_unix();
        let owners: Vec<Arc<dyn SessionOwner>> = guard(&self.aaa.shared.owners).clone();
        let Some((d, srv)) = &mut self.dynauth else {
            return;
        };
        // A dual-stack socket sees IPv4 senders as ::ffff:a.b.c.d.
        let canon = SocketAddr::new(from.ip().to_canonical(), from.port());
        let reply = match srv.handle(canon, data, unix, now) {
            Ok(Incoming::Resend(bytes)) => bytes,
            Ok(Incoming::Request(r)) => {
                let outcome = match r.precheck {
                    Some(c) => Outcome::Nak(c),
                    None => {
                        let req = coa_request(&self.dict, &r);
                        let mut out = None;
                        for o in &owners {
                            match o.handle(&req) {
                                CoaOutcome::NotMine => {}
                                CoaOutcome::Ack => {
                                    out = Some(Outcome::Ack);
                                    break;
                                }
                                CoaOutcome::Nak(n) => {
                                    out = Some(Outcome::Nak(
                                        ErrorCause::from_u32(n)
                                            .unwrap_or(ErrorCause::ResourcesUnavailable),
                                    ));
                                    break;
                                }
                            }
                        }
                        out.unwrap_or(Outcome::Nak(ErrorCause::SessionContextNotFound))
                    }
                };
                let what = match r.kind {
                    RequestKind::Coa => "CoA",
                    RequestKind::Disconnect => "Disconnect",
                };
                let bytes = srv.respond(&r, outcome, &AttrList::new(), unix);
                let msg = match outcome {
                    Outcome::Ack | Outcome::AckResidualRemoved => {
                        format!("RADIUS: {what} de {} aceito", canon.ip())
                    }
                    Outcome::Nak(c) => {
                        format!(
                            "RADIUS: {what} de {} recusado (Error-Cause {})",
                            canon.ip(),
                            c.value()
                        )
                    }
                };
                let sock = d.socket.clone();
                let _ = sock.send_to(&bytes, from);
                self.log("info", msg);
                return;
            }
            // RFC 5176 §5: dropped without a reply (counted).
            Err(_) => return,
        };
        let _ = d.socket.send_to(&reply, from);
    }

    /// Send what the clients want sent, handle their timers and events.
    fn turn(&mut self) {
        let now = self.ms();
        for r in self.interims.due(now) {
            self.send_acct(r, now);
        }
        let mut lanes: Vec<&mut Lane> = self.lanes.values_mut().collect();
        lanes.extend(self.retiring.iter_mut());
        let mut logs = Vec::new();
        for lane in lanes {
            lane.client.handle_timeout(now);
            while let Some(t) = lane.client.poll_transmit(&mut self.buf) {
                let sock = match lane.sockets.get(&t.from) {
                    Some(s) => Some(s.socket.clone()),
                    None => open_socket(lane, t.from, t.dest, &self.aaa.tx, &mut logs),
                };
                if let Some(s) = sock {
                    let _ = s.send_to(&self.buf, t.dest);
                }
            }
            while let Some(ev) = lane.client.poll_event() {
                event(&self.dict, lane, ev, &mut logs);
            }
        }
        for (level, msg) in logs {
            self.log(level, msg);
        }
        // Lanes retired and drained: their counters join the totals.
        let mut i = 0;
        while i < self.retiring.len() {
            if self
                .retiring
                .get(i)
                .is_some_and(|l| l.client.pending() == 0)
            {
                let l = self.retiring.swap_remove(i);
                self.absorb(&l);
            } else {
                i += 1;
            }
        }
    }

    fn next_wait(&self) -> Duration {
        let now = self.ms();
        let mut t: Option<u64> = self.interims.next_due();
        for l in self.lanes.values().chain(self.retiring.iter()) {
            if let Some(x) = l.client.poll_timeout() {
                t = Some(t.map_or(x, |y| y.min(x)));
            }
        }
        match t {
            Some(t) => Duration::from_millis(t.saturating_sub(now)).min(MAX_WAIT),
            None => MAX_WAIT,
        }
    }

    fn publish(&mut self) {
        let mut st = RadiusStatus::default();
        for e in &self.cfg.servers {
            let mut m = ServerMonitor {
                id: e.id,
                address: Some(e.address),
                state: if e.disabled {
                    ServerState::Disabled
                } else {
                    ServerState::Idle
                },
                pending: 0,
                requests: 0,
                accepts: 0,
                rejects: 0,
                acct_responses: 0,
                resends: 0,
                timeouts: 0,
                bad_replies: 0,
                unsolicited: 0,
                last_request_rtt: 0,
                sockets: 0,
            };
            let mut total = self.base.get(&e.id).copied().unwrap_or_default();
            let mut down = false;
            let mut seen = false;
            for l in self.lanes.values().chain(self.retiring.iter()) {
                for (i, r) in l.spec.refs.iter().enumerate() {
                    if r.id != e.id {
                        continue;
                    }
                    if let Some(s) = l.client.stats(i) {
                        add_stats(&mut total, &s, true);
                    }
                    if self.lanes.values().any(|x| x.id == l.id) {
                        seen = true;
                        down |= !l.client.is_alive(i);
                    }
                }
            }
            if seen {
                m.state = match (down, e.status_server) {
                    (false, _) => ServerState::Up,
                    (true, false) => ServerState::Down,
                    (true, true) => ServerState::Probing,
                };
            }
            m.pending = total.in_flight;
            m.requests = total.requests;
            m.accepts = total.accepts;
            m.rejects = total.rejects;
            m.acct_responses = total.acct_responses;
            m.resends = total.resends;
            m.timeouts = total.timeouts;
            m.bad_replies = total.bad_replies;
            m.unsolicited = total.unsolicited;
            m.last_request_rtt = total.last_rtt_ms;
            m.sockets = total.sockets;
            st.pending += m.pending;
            st.servers.push(m);
        }
        let mut d = self.dyn_stats_base;
        let mut inc = IncomingMonitor {
            owners: guard(&self.aaa.shared.owners).len() as u64,
            last_error: self.incoming_error.clone(),
            ..IncomingMonitor::default()
        };
        if let Some((sock, srv)) = &self.dynauth {
            add_dyn(&mut d, &srv.stats());
            inc.listening = Some(format!("udp {}", sock.at));
        }
        inc.requests = d.requests;
        inc.acks = d.acks;
        inc.naks = d.naks;
        inc.dropped = d.dropped;
        inc.duplicates = d.duplicates;
        st.incoming = inc;
        *guard(&self.aaa.shared.status) = st;
        self.last_status = Instant::now();
    }
}

fn submit_error(e: &SubmitError) -> String {
    match e {
        SubmitError::NoServer => "no RADIUS server for this request".into(),
        SubmitError::Busy => {
            "too many requests pending (the servers are slower than the load)".into()
        }
        SubmitError::Encode(e) => format!("request too large: {e}"),
    }
}

/// `into += s`; `live` sums the instantaneous fields too (in flight,
/// sockets), a retired lane keeps only its counters.
fn add_stats(into: &mut ServerStats, s: &ServerStats, live: bool) {
    into.requests += s.requests;
    into.accepts += s.accepts;
    into.rejects += s.rejects;
    into.challenges += s.challenges;
    into.acct_responses += s.acct_responses;
    into.resends += s.resends;
    into.timeouts += s.timeouts;
    into.bad_replies += s.bad_replies;
    into.unsolicited += s.unsolicited;
    if s.last_rtt_ms > 0 {
        into.last_rtt_ms = s.last_rtt_ms;
    }
    if live {
        into.in_flight += s.in_flight;
        into.sockets += s.sockets;
    }
}

fn add_dyn(
    into: &mut corerouter_proto_radius::dynauth::DynAuthStats,
    s: &corerouter_proto_radius::dynauth::DynAuthStats,
) {
    into.requests += s.requests;
    into.duplicates += s.duplicates;
    into.dropped += s.dropped;
    into.acks += s.acks;
    into.naks += s.naks;
}

fn dyn_config(want: &(RadiusIncoming, Vec<(IpAddr, String)>)) -> DynAuthConfig {
    let (inc, clients) = want;
    DynAuthConfig {
        clients: clients
            .iter()
            .map(|(addr, secret)| DynAuthClient {
                addr: *addr,
                secret: secret.as_bytes().to_vec(),
            })
            .collect(),
        replay_window_secs: inc.replay_window,
        require_event_timestamp: inc.require_event_timestamp,
        require_message_authenticator: inc.require_message_auth,
        ..DynAuthConfig::default()
    }
}

fn coa_request(dict: &Dictionary, r: &DynAuthRequest) -> CoaRequest {
    let s = &r.selector;
    CoaRequest {
        kind: match r.kind {
            RequestKind::Coa => CoaKind::Coa,
            RequestKind::Disconnect => CoaKind::Disconnect,
        },
        from: r.from,
        selector: CoaSelector {
            user_name: s.user_name.clone(),
            acct_session_id: s.acct_session_id.clone(),
            framed_ip: s.framed_ip,
            nas_port_id: s.nas_port_id.clone(),
            calling_station_id: s.calling_station_id.clone(),
        },
        changes: decode_list(dict, &r.changes),
        authorize_only: r.authorize_only,
        packet: r.packet.clone(),
    }
}

fn open_socket(
    lane: &mut Lane,
    key: SocketKey,
    dest: SocketAddr,
    tx: &Sender<Msg>,
    logs: &mut Vec<(&'static str, String)>,
) -> Option<Arc<UdpSocket>> {
    let (src, vrf) = lane
        .spec
        .binds
        .get(key.server)
        .cloned()
        .unwrap_or((None, "main".into()));
    let opened = bind_udp(src, dest.is_ipv4(), &vrf, 0).and_then(|s| {
        let socket = Arc::new(s);
        let stop = Arc::new(AtomicBool::new(false));
        let id = lane.id;
        reader(
            socket.clone(),
            stop.clone(),
            tx.clone(),
            move |from, data| Msg::Datagram {
                lane: id,
                key,
                from,
                data,
            },
        )?;
        Ok(Sock { socket, stop })
    });
    match opened {
        Ok(s) => {
            let out = s.socket.clone();
            lane.sockets.insert(key, s);
            Some(out)
        }
        Err(e) => {
            if let Some(f) = lane.bind_failed.get_mut(key.server)
                && !*f
            {
                *f = true;
                let from = src.map_or_else(|| "qualquer endereço".to_owned(), |a| a.to_string());
                logs.push((
                    "error",
                    format!("RADIUS: não consegui abrir socket UDP de {from} (vrf {vrf}) para {dest}: {e}"),
                ));
            }
            None
        }
    }
}

fn event(dict: &Dictionary, lane: &mut Lane, ev: Event, logs: &mut Vec<(&'static str, String)>) {
    let addr = |i: usize| lane.client.server(i).map(|s| s.addr);
    match ev {
        Event::Response {
            request,
            server,
            code,
            packet,
            request_authenticator,
            rtt_ms,
        } => match lane.waiting.remove(&request) {
            Some(Waiting::Auth { done, realm_user }) => {
                let outcome = match code {
                    Code::AccessAccept => AuthOutcome::Accept,
                    Code::AccessReject => AuthOutcome::Reject,
                    Code::AccessChallenge => AuthOutcome::Challenge,
                    _ => AuthOutcome::Error,
                };
                let (attributes, message) = match Packet::parse(&packet) {
                    Ok(p) => (
                        decode_all(dict, &p),
                        p.attr(attr::REPLY_MESSAGE)
                            .map(|m| String::from_utf8_lossy(m).chars().take(253).collect()),
                    ),
                    Err(_) => (Vec::new(), None),
                };
                if outcome == AuthOutcome::Reject {
                    logs.push((
                        "info",
                        format!(
                            "RADIUS: {realm_user} recusado por {}",
                            addr(server).map_or_else(String::new, |a| a.ip().to_string())
                        ),
                    ));
                }
                done(AuthReply {
                    outcome,
                    server: lane.spec.refs.get(server).map(|r| r.id),
                    server_address: addr(server).map(|a| a.ip()),
                    rtt_ms: Some(rtt_ms),
                    attributes,
                    message,
                    packet,
                    request_authenticator,
                });
            }
            Some(Waiting::Acct { .. }) | None => {}
        },
        Event::Failed { request, reason } => match lane.waiting.remove(&request) {
            Some(Waiting::Auth { done, realm_user }) => {
                let tried = lane
                    .spec
                    .refs
                    .iter()
                    .filter(|r| r.service == Service::Auth)
                    .count();
                let msg = match reason {
                    Failure::Timeout => format!("no RADIUS server answered ({tried} tried)"),
                    Failure::Superseded | Failure::Cancelled => "cancelled".to_owned(),
                };
                logs.push((
                    "warning",
                    format!(
                        "RADIUS: nenhum servidor respondeu por {realm_user} ({tried} tentados)"
                    ),
                ));
                done(AuthReply::failed(AuthOutcome::Timeout, msg));
            }
            Some(Waiting::Acct { session, status }) if reason == Failure::Timeout => {
                let what = match status {
                    AcctStatus::Start => "Start",
                    AcctStatus::InterimUpdate => "Interim-Update",
                    AcctStatus::Stop => "Stop",
                };
                logs.push((
                    "warning",
                    format!("RADIUS: contabilização {what} de {session} perdida: nenhum servidor confirmou"),
                ));
            }
            Some(Waiting::Acct { .. }) => {}
            None => {}
        },
        Event::ServerDown { server } => {
            if let Some(a) = addr(server) {
                logs.push((
                    "warning",
                    format!(
                        "RADIUS: servidor {a} ({}) fora do ar; usando o próximo da lista",
                        lane.service.as_str()
                    ),
                ));
            }
        }
        Event::ServerUp { server } => {
            if let Some(a) = addr(server) {
                logs.push((
                    "info",
                    format!("RADIUS: servidor {a} ({}) voltou", lane.service.as_str()),
                ));
            }
        }
    }
}

/// The driver's loop: until [`Aaa::stop`] or `stopping()` (the
/// supervisor). Answers every request still waiting with an error when it
/// ends, so no caller waits forever.
pub fn run(aaa: &Aaa, inbox: &Inbox, stopping: &dyn Fn() -> bool) {
    let rx = guard(&inbox.0);
    let mut d = Driver {
        aaa,
        t0: Instant::now(),
        dict: Dictionary::builtin(),
        cfg: AaaConfig::default(),
        lanes: BTreeMap::new(),
        retiring: Vec::new(),
        next_lane: 0,
        base: HashMap::new(),
        interims: Interims::default(),
        dynauth: None,
        dyn_stats_base: Default::default(),
        incoming_error: None,
        buf: Vec::with_capacity(4096),
        last_status: Instant::now(),
    };
    'outer: loop {
        let wait = d.next_wait();
        let first = match rx.recv_timeout(wait) {
            Ok(m) => Some(m),
            Err(RecvTimeoutError::Timeout) => None,
            Err(RecvTimeoutError::Disconnected) => break,
        };
        let mut next = first;
        let mut n = 0;
        while let Some(m) = next.take() {
            match m {
                Msg::Auth(req, done) => {
                    aaa.shared.queued.fetch_sub(1, Ordering::Relaxed);
                    d.auth(*req, done);
                }
                Msg::Acct(req, src) => {
                    aaa.shared.queued.fetch_sub(1, Ordering::Relaxed);
                    d.acct(*req, src);
                }
                Msg::Datagram {
                    lane,
                    key,
                    from,
                    data,
                } => d.datagram(lane, key, from, &data),
                Msg::DynAuth { from, data } => d.dyn_auth(from, &data),
                Msg::Reload(cfg) => {
                    if *cfg != d.cfg {
                        d.reload(*cfg);
                    }
                }
                Msg::Stop => break 'outer,
            }
            n += 1;
            if n >= BURST {
                break;
            }
            next = rx.try_recv().ok();
        }
        d.turn();
        if d.last_status.elapsed() >= STATUS_EVERY {
            d.publish();
        }
        if stopping() {
            break;
        }
    }
    // Whoever still waits gets an answer.
    let lanes: Vec<Lane> = std::mem::take(&mut d.lanes)
        .into_values()
        .chain(std::mem::take(&mut d.retiring))
        .collect();
    for mut l in lanes {
        for (_, w) in l.waiting.drain() {
            if let Waiting::Auth { done, .. } = w {
                done(AuthReply::failed(
                    AuthOutcome::Error,
                    "the radius service stopped",
                ));
            }
        }
    }
    while let Ok(m) = rx.try_recv() {
        if let Msg::Auth(_, done) = m {
            aaa.shared.queued.fetch_sub(1, Ordering::Relaxed);
            done(AuthReply::failed(
                AuthOutcome::Error,
                "the radius service stopped",
            ));
        }
    }
    d.publish();
}

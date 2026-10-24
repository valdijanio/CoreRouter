//! Sans-IO Dynamic Authorization Server (the NAS side of RFC 5176):
//! CoA-Request and Disconnect-Request from a billing system.
//!
//! [`DynAuthServer::handle`] checks a datagram and either drops it silently,
//! answers a duplicate from the cache, or hands the caller a
//! [`DynAuthRequest`]: who sent it, the session selector, the authorization
//! changes and, when the RFC already decides the answer, the Error-Cause to
//! NAK with. The caller finds the matching sessions
//! ([`SessionSelector::matches`]), applies the change to all of them or to
//! none (RFC 5176 §2.3: "State changes resulting from a CoA-Request MUST be
//! atomic"), and answers with [`DynAuthServer::respond`].
//!
//! Rules implemented, by section of RFC 5176:
//!
//! - §2.3: only CoA-Request and Disconnect-Request; the Request
//!   Authenticator is computed like an Accounting-Request's; the secret is
//!   chosen by source address; unknown sources are silently discarded.
//! - §2.3 + RFC 5080 §2.2.2: duplicate detection by source address, port,
//!   identifier and authenticator, answered from the cache.
//! - §3.1: Proxy-State echoed in order; §3.3: State echoed unmodified.
//! - §3.2: Service-Type "Authorize Only" needs a State (402) and only
//!   identification attributes (401); the NAS answers CoA-NAK 507 and sends
//!   an Access-Request — exposed as [`DynAuthRequest::authorize_only`].
//! - §3: a Disconnect-Request carries only identification attributes (401);
//!   some session identification is needed (402); NAS identification must
//!   match the NAS (403).
//! - §3.4: a Message-Authenticator, when present, must be valid (optionally
//!   required); responses always carry one.
//! - §3.5: Error-Cause 2xx only in ACKs, 4xx/5xx only in NAKs.
//! - §6.3: Event-Timestamp within the window (default 300 s, optionally
//!   required); the duplicate cache keeps entries for the same window.

use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use thiserror::Error;

use crate::crypto::{self, MaCheck};
use crate::dict::{AttrId, Dictionary, DynAuthRole};
use crate::packet::{AttrList, Builder, Code, Packet, PushAttr, VendorSpecific, attr};

/// RFC 5176 §3.5 Error-Cause values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCause {
    ResidualSessionContextRemoved = 201,
    InvalidEapPacket = 202,
    UnsupportedAttribute = 401,
    MissingAttribute = 402,
    NasIdentificationMismatch = 403,
    InvalidRequest = 404,
    UnsupportedService = 405,
    UnsupportedExtension = 406,
    InvalidAttributeValue = 407,
    AdministrativelyProhibited = 501,
    RequestNotRoutable = 502,
    SessionContextNotFound = 503,
    SessionContextNotRemovable = 504,
    OtherProxyProcessingError = 505,
    ResourcesUnavailable = 506,
    RequestInitiated = 507,
    MultipleSessionSelectionUnsupported = 508,
}

impl ErrorCause {
    pub fn from_u32(v: u32) -> Option<Self> {
        use ErrorCause as E;
        Some(match v {
            201 => E::ResidualSessionContextRemoved,
            202 => E::InvalidEapPacket,
            401 => E::UnsupportedAttribute,
            402 => E::MissingAttribute,
            403 => E::NasIdentificationMismatch,
            404 => E::InvalidRequest,
            405 => E::UnsupportedService,
            406 => E::UnsupportedExtension,
            407 => E::InvalidAttributeValue,
            501 => E::AdministrativelyProhibited,
            502 => E::RequestNotRoutable,
            503 => E::SessionContextNotFound,
            504 => E::SessionContextNotRemovable,
            505 => E::OtherProxyProcessingError,
            506 => E::ResourcesUnavailable,
            507 => E::RequestInitiated,
            508 => E::MultipleSessionSelectionUnsupported,
            _ => return None,
        })
    }

    pub fn value(self) -> u32 {
        self as u32
    }

    /// §3.5: 200–299 "may only be sent within CoA-ACK or Disconnect-ACK".
    pub fn is_success(self) -> bool {
        (200..300).contains(&self.value())
    }
}

/// Service-Type "Authorize Only" (RFC 3576/5176 §3.2).
pub const SERVICE_TYPE_AUTHORIZE_ONLY: u32 = 17;

/// A Dynamic Authorization Client allowed to send requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynAuthClient {
    pub addr: IpAddr,
    pub secret: Vec<u8>,
}

/// The NAS's own identity, for the 403 check. Empty lists skip it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NasIdentity {
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
    pub identifier: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynAuthConfig {
    pub clients: Vec<DynAuthClient>,
    pub nas: NasIdentity,
    /// §6.3 window, seconds (also the duplicate-cache lifetime).
    pub replay_window_secs: u32,
    /// §6.3: "SHOULD be configurable to discard ... not containing an
    /// Event-Timestamp". Off by default: MikroTik and most billing systems
    /// do not send it.
    pub require_event_timestamp: bool,
    /// Require a Message-Authenticator in requests (off by default for the
    /// same reason).
    pub require_message_authenticator: bool,
    /// Cache entries (memory bound against a flood from a known client).
    pub max_cache: usize,
}

impl Default for DynAuthConfig {
    fn default() -> Self {
        Self {
            clients: Vec::new(),
            nas: NasIdentity::default(),
            replay_window_secs: 300,
            require_event_timestamp: false,
            require_message_authenticator: false,
            max_cache: 65_536,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum Drop {
    #[error("source is not an allowed client")]
    UnknownClient,
    #[error("malformed packet")]
    Malformed,
    #[error("not a CoA-Request or Disconnect-Request")]
    NotARequest,
    #[error("bad Request Authenticator")]
    BadAuthenticator,
    #[error("bad Message-Authenticator")]
    BadMessageAuthenticator,
    #[error("Message-Authenticator required")]
    MissingMessageAuthenticator,
    #[error("Event-Timestamp outside the window")]
    StaleTimestamp,
    #[error("Event-Timestamp required")]
    MissingTimestamp,
    #[error("duplicate of a request still being processed")]
    InProgress,
    #[error("duplicate cache full")]
    CacheFull,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    Disconnect,
    Coa,
}

/// Session identification attributes (§3), owned.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionSelector {
    pub user_name: Option<String>,
    pub acct_session_id: Option<String>,
    pub acct_multi_session_id: Option<String>,
    pub framed_ip: Option<Ipv4Addr>,
    pub framed_ipv6_prefix: Option<(Ipv6Addr, u8)>,
    pub framed_interface_id: Option<[u8; 8]>,
    pub nas_port: Option<u32>,
    pub nas_port_id: Option<String>,
    pub calling_station_id: Option<String>,
    pub called_station_id: Option<String>,
    pub cui: Option<Vec<u8>>,
    /// Identification VSAs (RFC 4679 Agent-Circuit-Id / Agent-Remote-Id…).
    pub vsas: Vec<(u32, u8, Vec<u8>)>,
}

/// What a session looks like to the selector. Fields the NAS does not
/// track stay `None` and never match a selector that names them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SessionView<'a> {
    pub user_name: Option<&'a str>,
    pub acct_session_id: Option<&'a str>,
    pub acct_multi_session_id: Option<&'a str>,
    pub framed_ip: Option<Ipv4Addr>,
    pub framed_ipv6_prefix: Option<(Ipv6Addr, u8)>,
    pub framed_interface_id: Option<[u8; 8]>,
    pub nas_port: Option<u32>,
    pub nas_port_id: Option<&'a str>,
    pub calling_station_id: Option<&'a str>,
    pub called_station_id: Option<&'a str>,
    pub cui: Option<&'a [u8]>,
    pub vsas: &'a [(u32, u8, &'a [u8])],
}

fn same<T: PartialEq + ?Sized>(want: Option<&T>, have: Option<&T>) -> bool {
    match want {
        None => true,
        Some(w) => have == Some(w),
    }
}

impl SessionSelector {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Every attribute the request names must match (§3: "the combination
    /// ... MUST match").
    pub fn matches(&self, s: &SessionView<'_>) -> bool {
        same(self.user_name.as_deref(), s.user_name)
            && same(self.acct_session_id.as_deref(), s.acct_session_id)
            && same(
                self.acct_multi_session_id.as_deref(),
                s.acct_multi_session_id,
            )
            && same(self.framed_ip.as_ref(), s.framed_ip.as_ref())
            && same(
                self.framed_ipv6_prefix.as_ref(),
                s.framed_ipv6_prefix.as_ref(),
            )
            && same(
                self.framed_interface_id.as_ref(),
                s.framed_interface_id.as_ref(),
            )
            && same(self.nas_port.as_ref(), s.nas_port.as_ref())
            && same(self.nas_port_id.as_deref(), s.nas_port_id)
            && same(self.calling_station_id.as_deref(), s.calling_station_id)
            && same(self.called_station_id.as_deref(), s.called_station_id)
            && same(self.cui.as_deref(), s.cui)
            && self.vsas.iter().all(|(v, t, val)| {
                s.vsas
                    .iter()
                    .any(|(sv, st, sval)| sv == v && st == t && *sval == val.as_slice())
            })
    }

    /// Indexes of the matching sessions.
    pub fn select<'a>(&self, sessions: impl IntoIterator<Item = SessionView<'a>>) -> Vec<usize> {
        sessions
            .into_iter()
            .enumerate()
            .filter(|(_, s)| self.matches(s))
            .map(|(i, _)| i)
            .collect()
    }
}

/// A checked request for the caller to act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynAuthRequest {
    pub kind: RequestKind,
    pub from: SocketAddr,
    /// Index in [`DynAuthConfig::clients`].
    pub client: usize,
    pub identifier: u8,
    pub authenticator: [u8; 16],
    pub selector: SessionSelector,
    /// §3.2: Service-Type Authorize Only. The answer is CoA-NAK 507 (with
    /// Service-Type) and an Access-Request carrying [`Self::state`].
    pub authorize_only: bool,
    pub state: Option<Vec<u8>>,
    /// Authorization changes (Notes 3, 5 and 7), plus Reply-Message,
    /// Class and Acct-Terminate-Cause as received.
    pub changes: AttrList,
    /// The NAK the RFC already requires, if any.
    pub precheck: Option<ErrorCause>,
    /// The request as received.
    pub packet: Vec<u8>,
}

impl DynAuthRequest {
    /// Error-Cause 401 when an attribute of `changes` is not supported
    /// (§2.3: "all attributes MUST be treated as mandatory"). `supported`
    /// gets the flattened id of each change.
    pub fn check_supported(&self, mut supported: impl FnMut(AttrId) -> bool) -> Option<ErrorCause> {
        for a in self.changes.iter() {
            if a.typ == attr::VENDOR_SPECIFIC {
                let Some(vs) = VendorSpecific::parse(a.value) else {
                    return Some(ErrorCause::InvalidAttributeValue);
                };
                for v in vs {
                    if !supported(AttrId::Vendor(v.vendor, v.typ)) {
                        return Some(ErrorCause::UnsupportedAttribute);
                    }
                }
            } else if !supported(AttrId::Std(a.typ)) {
                return Some(ErrorCause::UnsupportedAttribute);
            }
        }
        None
    }
}

/// The caller's decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ack,
    /// Disconnect-ACK with Error-Cause 201 (residual context removed).
    AckResidualRemoved,
    Nak(ErrorCause),
}

pub enum Incoming {
    Request(Box<DynAuthRequest>),
    /// A retransmission already answered: send these bytes again.
    Resend(Vec<u8>),
}

#[derive(Debug, Clone)]
struct CacheEntry {
    authenticator: [u8; 16],
    response: Option<Vec<u8>>,
    expires_ms: u64,
}

/// Counters, per drop reason and outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DynAuthStats {
    pub requests: u64,
    pub duplicates: u64,
    pub dropped: u64,
    pub acks: u64,
    pub naks: u64,
}

pub struct DynAuthServer {
    cfg: DynAuthConfig,
    dict: Dictionary,
    cache: HashMap<(SocketAddr, u8), CacheEntry>,
    expiry: VecDeque<(u64, SocketAddr, u8)>,
    stats: DynAuthStats,
}

impl std::fmt::Debug for DynAuthServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynAuthServer")
            .field("clients", &self.cfg.clients.len())
            .field("cache", &self.cache.len())
            .finish_non_exhaustive()
    }
}

/// Keep the first precheck error.
fn flag(e: ErrorCause, slot: &mut Option<ErrorCause>) {
    if slot.is_none() {
        *slot = Some(e);
    }
}

fn text(v: &[u8]) -> Option<String> {
    std::str::from_utf8(v).ok().map(str::to_owned)
}

impl DynAuthServer {
    pub fn new(cfg: DynAuthConfig) -> Self {
        Self::with_dictionary(cfg, Dictionary::builtin())
    }

    /// With a dictionary carrying extra vendor attributes (their
    /// [`DynAuthRole`] decides identification versus change).
    pub fn with_dictionary(cfg: DynAuthConfig, dict: Dictionary) -> Self {
        Self {
            cfg,
            dict,
            cache: HashMap::new(),
            expiry: VecDeque::new(),
            stats: DynAuthStats::default(),
        }
    }

    pub fn stats(&self) -> DynAuthStats {
        self.stats
    }

    pub fn config(&self) -> &DynAuthConfig {
        &self.cfg
    }

    fn purge(&mut self, now_ms: u64) {
        while let Some(&(t, addr, id)) = self.expiry.front() {
            if t > now_ms {
                break;
            }
            self.expiry.pop_front();
            if self
                .cache
                .get(&(addr, id))
                .is_some_and(|e| e.expires_ms <= now_ms)
            {
                self.cache.remove(&(addr, id));
            }
        }
    }

    /// Check one datagram. `now_unix` is wall-clock seconds (Event-Timestamp),
    /// `now_ms` a monotonic clock (cache expiry).
    pub fn handle(
        &mut self,
        from: SocketAddr,
        data: &[u8],
        now_unix: u32,
        now_ms: u64,
    ) -> Result<Incoming, Drop> {
        let r = self.check(from, data, now_unix, now_ms);
        match &r {
            Ok(Incoming::Request(_)) => self.stats.requests += 1,
            Ok(Incoming::Resend(_)) => self.stats.duplicates += 1,
            Err(Drop::InProgress) => self.stats.duplicates += 1,
            Err(_) => self.stats.dropped += 1,
        }
        r
    }

    fn check(
        &mut self,
        from: SocketAddr,
        data: &[u8],
        now_unix: u32,
        now_ms: u64,
    ) -> Result<Incoming, Drop> {
        let client = self
            .cfg
            .clients
            .iter()
            .position(|c| c.addr == from.ip())
            .ok_or(Drop::UnknownClient)?;
        let secret = self
            .cfg
            .clients
            .get(client)
            .map(|c| c.secret.clone())
            .unwrap_or_default();
        let p = Packet::parse(data).map_err(|_| Drop::Malformed)?;
        let kind = match p.code() {
            Code::CoaRequest => RequestKind::Coa,
            Code::DisconnectRequest => RequestKind::Disconnect,
            _ => return Err(Drop::NotARequest),
        };
        if !crypto::verify_computed_request(&p, &secret) {
            return Err(Drop::BadAuthenticator);
        }
        match crypto::check_message_authenticator(&p, &[0; 16], &secret) {
            MaCheck::Invalid => return Err(Drop::BadMessageAuthenticator),
            MaCheck::Absent if self.cfg.require_message_authenticator => {
                return Err(Drop::MissingMessageAuthenticator);
            }
            _ => {}
        }
        match p.attr_u32(attr::EVENT_TIMESTAMP) {
            Some(ts) => {
                if now_unix.abs_diff(ts) > self.cfg.replay_window_secs {
                    return Err(Drop::StaleTimestamp);
                }
            }
            None if self.cfg.require_event_timestamp => return Err(Drop::MissingTimestamp),
            None => {}
        }
        self.purge(now_ms);
        let key = (from, p.identifier());
        let auth = p.authenticator();
        if let Some(e) = self.cache.get(&key) {
            if e.authenticator == auth {
                return match &e.response {
                    Some(bytes) => Ok(Incoming::Resend(bytes.clone())),
                    None => Err(Drop::InProgress),
                };
            }
            // RFC 5080 §2.2.2: same source and identifier, new
            // authenticator: a new request replaces the entry.
            self.cache.remove(&key);
        }
        if self.cache.len() >= self.cfg.max_cache {
            return Err(Drop::CacheFull);
        }
        let expires_ms = now_ms + u64::from(self.cfg.replay_window_secs) * 1000;
        self.cache.insert(
            key,
            CacheEntry {
                authenticator: auth,
                response: None,
                expires_ms,
            },
        );
        self.expiry.push_back((expires_ms, from, p.identifier()));
        Ok(Incoming::Request(Box::new(
            self.classify(&p, kind, from, client),
        )))
    }

    fn classify(
        &self,
        p: &Packet<'_>,
        kind: RequestKind,
        from: SocketAddr,
        client: usize,
    ) -> DynAuthRequest {
        let mut sel = SessionSelector::default();
        let mut changes = AttrList::new();
        let mut precheck = None;
        let mut nas_mismatch = false;
        let mut service_type = None;
        let mut states = 0;
        let mut state = None;
        let mut other_than_ids = false;
        let nas = &self.cfg.nas;
        for a in p.attributes() {
            let v = a.value;
            match a.typ {
                attr::USER_NAME => sel.user_name = text(v),
                attr::ACCT_SESSION_ID => sel.acct_session_id = text(v),
                attr::ACCT_MULTI_SESSION_ID => sel.acct_multi_session_id = text(v),
                attr::FRAMED_IP_ADDRESS => {
                    // Table §3.6 lists 0 for Disconnect, §3 lists it as a
                    // session identifier: accepted (RouterOS and billing
                    // systems send it).
                    sel.framed_ip = <[u8; 4]>::try_from(v).ok().map(Ipv4Addr::from);
                    if sel.framed_ip.is_none() {
                        flag(ErrorCause::InvalidAttributeValue, &mut precheck);
                    }
                }
                attr::FRAMED_IPV6_PREFIX => {
                    sel.framed_ipv6_prefix = crate::dict::decode_ipv6_prefix(v);
                    if sel.framed_ipv6_prefix.is_none() {
                        flag(ErrorCause::InvalidAttributeValue, &mut precheck);
                    }
                }
                attr::FRAMED_INTERFACE_ID => sel.framed_interface_id = <[u8; 8]>::try_from(v).ok(),
                attr::NAS_PORT => sel.nas_port = crate::packet::be_u32(v),
                attr::NAS_PORT_ID => sel.nas_port_id = text(v),
                attr::CALLING_STATION_ID => sel.calling_station_id = text(v),
                attr::CALLED_STATION_ID => sel.called_station_id = text(v),
                attr::CHARGEABLE_USER_IDENTITY => sel.cui = Some(v.to_vec()),
                attr::NAS_IP_ADDRESS => {
                    let ok = <[u8; 4]>::try_from(v).is_ok_and(|b| {
                        nas.ipv4.is_empty() || nas.ipv4.contains(&Ipv4Addr::from(b))
                    });
                    nas_mismatch |= !ok;
                }
                attr::NAS_IPV6_ADDRESS => {
                    let ok = <[u8; 16]>::try_from(v).is_ok_and(|b| {
                        nas.ipv6.is_empty() || nas.ipv6.contains(&Ipv6Addr::from(b))
                    });
                    nas_mismatch |= !ok;
                }
                attr::NAS_IDENTIFIER => {
                    nas_mismatch |= nas
                        .identifier
                        .as_deref()
                        .is_some_and(|id| id.as_bytes() != v);
                }
                attr::STATE => {
                    states += 1;
                    state = Some(v.to_vec());
                }
                attr::SERVICE_TYPE => service_type = crate::packet::be_u32(v),
                attr::PROXY_STATE | attr::MESSAGE_AUTHENTICATOR | attr::EVENT_TIMESTAMP => {}
                attr::REPLY_MESSAGE
                | attr::CLASS
                | attr::ACCT_TERMINATE_CAUSE
                | attr::EAP_MESSAGE => {
                    let _ = changes.push(a.typ, v);
                }
                attr::VENDOR_SPECIFIC => {
                    // Note 7: a VSA identifies or changes, by its role.
                    let Some(vs) = VendorSpecific::parse(v).filter(VendorSpecific::is_well_formed)
                    else {
                        flag(ErrorCause::InvalidAttributeValue, &mut precheck);
                        continue;
                    };
                    let mut change = false;
                    for s in vs {
                        let role = self
                            .dict
                            .get(AttrId::Vendor(s.vendor, s.typ))
                            .map(|d| d.dynauth);
                        if role == Some(DynAuthRole::Session) {
                            sel.vsas.push((s.vendor, s.typ, s.value.to_vec()));
                        } else {
                            change = true;
                        }
                    }
                    if change {
                        other_than_ids = true;
                        let _ = changes.push(a.typ, v);
                    }
                }
                t => {
                    let role = self.dict.get(AttrId::Std(t)).map(|d| d.dynauth);
                    match role {
                        Some(DynAuthRole::Authorization) | None => {
                            other_than_ids = true;
                            let _ = changes.push(t, v);
                        }
                        // Accounting counters, User-Password and the like
                        // mean nothing in CoA/DM.
                        _ => flag(ErrorCause::UnsupportedAttribute, &mut precheck),
                    }
                }
            }
        }
        if nas_mismatch {
            precheck = Some(ErrorCause::NasIdentificationMismatch);
        }
        let authorize_only =
            kind == RequestKind::Coa && service_type == Some(SERVICE_TYPE_AUTHORIZE_ONLY);
        match kind {
            RequestKind::Disconnect => {
                // §3: only identification attributes; §3.2: no
                // Service-Type; table §3.6: no State.
                if other_than_ids || service_type.is_some() || states > 0 {
                    flag(ErrorCause::UnsupportedAttribute, &mut precheck);
                }
            }
            RequestKind::Coa => {
                if states > 1 {
                    // §3.3: "zero or one State Attribute".
                    flag(ErrorCause::InvalidRequest, &mut precheck);
                }
                if authorize_only {
                    if state.is_none() {
                        flag(ErrorCause::MissingAttribute, &mut precheck);
                    }
                    if other_than_ids {
                        flag(ErrorCause::UnsupportedAttribute, &mut precheck);
                    }
                } else if service_type.is_some() {
                    // Changing the service of a running session is not
                    // something a BNG does (§3.5 405).
                    flag(ErrorCause::UnsupportedService, &mut precheck);
                }
            }
        }
        if sel.is_empty() {
            flag(ErrorCause::MissingAttribute, &mut precheck);
        }
        DynAuthRequest {
            kind,
            from,
            client,
            identifier: p.identifier(),
            authenticator: p.authenticator(),
            selector: sel,
            authorize_only,
            state,
            changes,
            precheck,
            packet: p.as_bytes().to_vec(),
        }
    }

    /// Build the ACK or NAK, remember it for duplicates, and return the
    /// bytes to send back to `req.from`. `extra` goes after the mandatory
    /// attributes (Service-Type for the 507 NAK, Reply-Message…).
    pub fn respond(
        &mut self,
        req: &DynAuthRequest,
        outcome: Outcome,
        extra: &AttrList,
        now_unix: u32,
    ) -> Vec<u8> {
        let code = match (req.kind, outcome) {
            (RequestKind::Coa, Outcome::Nak(_)) => Code::CoaNak,
            (RequestKind::Coa, _) => Code::CoaAck,
            (RequestKind::Disconnect, Outcome::Nak(_)) => Code::DisconnectNak,
            (RequestKind::Disconnect, _) => Code::DisconnectAck,
        };
        let mut b = Builder::new(code, req.identifier);
        let _ = b.message_authenticator();
        let cause = match outcome {
            Outcome::Nak(e) if !e.is_success() => Some(e),
            // §3.5: a 2xx in a NAK is not allowed; answer "Invalid Request"
            // rather than send a malformed NAK.
            Outcome::Nak(_) => Some(ErrorCause::InvalidRequest),
            Outcome::AckResidualRemoved if req.kind == RequestKind::Disconnect => {
                Some(ErrorCause::ResidualSessionContextRemoved)
            }
            _ => None,
        };
        if let Some(e) = cause {
            let _ = b.push_u32(attr::ERROR_CAUSE, e.value());
        }
        if let Some(s) = &req.state {
            let _ = b.push(attr::STATE, s);
        }
        let _ = b.push_u32(attr::EVENT_TIMESTAMP, now_unix);
        let _ = b.extend(extra);
        if let Ok(p) = Packet::parse(&req.packet) {
            for a in p.attributes().filter(|a| a.typ == attr::PROXY_STATE) {
                let _ = b.push(attr::PROXY_STATE, a.value);
            }
        }
        let secret = self
            .cfg
            .clients
            .get(req.client)
            .map(|c| c.secret.as_slice())
            .unwrap_or_default();
        let bytes = crypto::sign_response(b, &req.authenticator, secret);
        if let Some(e) = self.cache.get_mut(&(req.from, req.identifier))
            && e.authenticator == req.authenticator
        {
            e.response = Some(bytes.clone());
        }
        match outcome {
            Outcome::Nak(_) => self.stats.naks += 1,
            _ => self.stats.acks += 1,
        }
        bytes
    }
}

/// Build a CoA-Request or Disconnect-Request (the DAC side: tests, the lab,
/// and a future `/radius incoming` "send CoA" tool).
pub fn build_request(
    kind: RequestKind,
    identifier: u8,
    attrs: &AttrList,
    secret: &[u8],
    message_authenticator: bool,
) -> Vec<u8> {
    let code = match kind {
        RequestKind::Coa => Code::CoaRequest,
        RequestKind::Disconnect => Code::DisconnectRequest,
    };
    let mut b = Builder::new(code, identifier);
    if message_authenticator {
        let _ = b.message_authenticator();
    }
    let _ = b.extend(attrs);
    crypto::sign_request(b, secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dict::vendor;

    const NOW: u32 = 1_800_000_000;

    fn dac() -> SocketAddr {
        "10.9.9.9:40000".parse().unwrap()
    }

    fn server() -> DynAuthServer {
        DynAuthServer::new(DynAuthConfig {
            clients: vec![DynAuthClient {
                addr: dac().ip(),
                secret: b"coa-secret".to_vec(),
            }],
            nas: NasIdentity {
                ipv4: vec![Ipv4Addr::new(10, 0, 0, 1)],
                ..NasIdentity::default()
            },
            ..DynAuthConfig::default()
        })
    }

    fn req(kind: RequestKind, id: u8, f: impl FnOnce(&mut AttrList)) -> Vec<u8> {
        let mut l = AttrList::new();
        f(&mut l);
        build_request(kind, id, &l, b"coa-secret", true)
    }

    fn request(s: &mut DynAuthServer, bytes: &[u8]) -> DynAuthRequest {
        match s.handle(dac(), bytes, NOW, 0) {
            Ok(Incoming::Request(r)) => *r,
            Ok(Incoming::Resend(_)) => panic!("resend"),
            Err(e) => panic!("{e}"),
        }
    }

    #[test]
    fn coa_with_rate_limit_and_session_id() {
        let mut s = server();
        let bytes = req(RequestKind::Coa, 1, |l| {
            l.push_text(attr::ACCT_SESSION_ID, "PPP-77").unwrap();
            l.push_text(attr::USER_NAME, "ana").unwrap();
            l.push_ipv4(attr::NAS_IP_ADDRESS, Ipv4Addr::new(10, 0, 0, 1))
                .unwrap();
            l.push_vsa(vendor::MIKROTIK, 8, b"20M/50M").unwrap();
            l.push_vsa(vendor::DSL_FORUM, 1, b"olt1 pon 0/1/2").unwrap();
            l.push(attr::PROXY_STATE, b"p1").unwrap();
            l.push(attr::PROXY_STATE, b"p2").unwrap();
        });
        let r = request(&mut s, &bytes);
        assert_eq!(r.kind, RequestKind::Coa);
        assert_eq!(r.precheck, None);
        assert_eq!(r.selector.acct_session_id.as_deref(), Some("PPP-77"));
        assert_eq!(r.selector.vsas, vec![(3561, 1, b"olt1 pon 0/1/2".to_vec())]);
        assert_eq!(r.changes.iter().count(), 1);
        assert_eq!(r.check_supported(|id| id == AttrId::Vendor(14988, 8)), None);
        assert_eq!(
            r.check_supported(|_| false),
            Some(ErrorCause::UnsupportedAttribute)
        );

        let sessions = [
            SessionView {
                acct_session_id: Some("PPP-76"),
                user_name: Some("ana"),
                ..SessionView::default()
            },
            SessionView {
                acct_session_id: Some("PPP-77"),
                user_name: Some("ana"),
                vsas: &[(3561, 1, b"olt1 pon 0/1/2")],
                ..SessionView::default()
            },
        ];
        assert_eq!(r.selector.select(sessions.iter().cloned()), vec![1]);

        let ack = s.respond(&r, Outcome::Ack, &AttrList::new(), NOW);
        let p = Packet::parse(&ack).unwrap();
        assert_eq!(p.code(), Code::CoaAck);
        assert!(crypto::verify_response(&p, &r.authenticator, b"coa-secret"));
        assert_eq!(
            crypto::check_message_authenticator(&p, &r.authenticator, b"coa-secret"),
            MaCheck::Valid
        );
        let ps: Vec<_> = p
            .attributes()
            .filter(|a| a.typ == attr::PROXY_STATE)
            .map(|a| a.value)
            .collect();
        assert_eq!(ps, vec![&b"p1"[..], &b"p2"[..]]);
        // The retransmission gets the same bytes, without reprocessing.
        match s.handle(dac(), &bytes, NOW, 10) {
            Ok(Incoming::Resend(b)) => assert_eq!(b, ack),
            _ => panic!("expected a resend"),
        }
        assert_eq!(s.stats().duplicates, 1);
    }

    #[test]
    fn unknown_source_bad_secret_and_replies_are_dropped() {
        let mut s = server();
        let bytes = req(RequestKind::Disconnect, 1, |l| {
            l.push_text(attr::USER_NAME, "ana").unwrap();
        });
        let other: SocketAddr = "10.9.9.8:1".parse().unwrap();
        assert!(matches!(
            s.handle(other, &bytes, NOW, 0),
            Err(Drop::UnknownClient)
        ));
        let mut l = AttrList::new();
        l.push_text(attr::USER_NAME, "ana").unwrap();
        let forged = build_request(RequestKind::Disconnect, 1, &l, b"guess", false);
        assert!(matches!(
            s.handle(dac(), &forged, NOW, 0),
            Err(Drop::BadAuthenticator)
        ));
        let mut b = Builder::new(Code::CoaAck, 1);
        b.push_text(attr::USER_NAME, "x").unwrap();
        let ack = crypto::sign_request(b, b"coa-secret");
        assert!(matches!(
            s.handle(dac(), &ack, NOW, 0),
            Err(Drop::NotARequest)
        ));
        assert!(matches!(
            s.handle(dac(), &[1, 2, 3], NOW, 0),
            Err(Drop::Malformed)
        ));
        assert_eq!(s.stats().dropped, 4);
    }

    #[test]
    fn event_timestamp_window_rfc_5176_section_6_3() {
        let mut s = server();
        let at = |ts: u32, id: u8| {
            req(RequestKind::Disconnect, id, |l| {
                l.push_text(attr::USER_NAME, "ana").unwrap();
                l.push_u32(attr::EVENT_TIMESTAMP, ts).unwrap();
            })
        };
        assert!(matches!(
            s.handle(dac(), &at(NOW - 301, 1), NOW, 0),
            Err(Drop::StaleTimestamp)
        ));
        assert!(matches!(
            s.handle(dac(), &at(NOW + 301, 2), NOW, 0),
            Err(Drop::StaleTimestamp)
        ));
        assert!(matches!(
            s.handle(dac(), &at(NOW - 300, 3), NOW, 0),
            Ok(Incoming::Request(_))
        ));
        let mut strict = DynAuthServer::new(DynAuthConfig {
            require_event_timestamp: true,
            require_message_authenticator: true,
            ..s.config().clone()
        });
        let no_ts = req(RequestKind::Disconnect, 4, |l| {
            l.push_text(attr::USER_NAME, "ana").unwrap();
        });
        assert!(matches!(
            strict.handle(dac(), &no_ts, NOW, 0),
            Err(Drop::MissingTimestamp)
        ));
        let mut l = AttrList::new();
        l.push_text(attr::USER_NAME, "ana").unwrap();
        l.push_u32(attr::EVENT_TIMESTAMP, NOW).unwrap();
        let no_ma = build_request(RequestKind::Disconnect, 5, &l, b"coa-secret", false);
        assert!(matches!(
            strict.handle(dac(), &no_ma, NOW, 0),
            Err(Drop::MissingMessageAuthenticator)
        ));
    }

    #[test]
    fn duplicates_in_progress_and_new_authenticator() {
        let mut s = server();
        let a = req(RequestKind::Disconnect, 7, |l| {
            l.push_text(attr::USER_NAME, "ana").unwrap();
        });
        let _ = request(&mut s, &a);
        assert!(matches!(s.handle(dac(), &a, NOW, 5), Err(Drop::InProgress)));
        // Same identifier, different content: a new request.
        let b = req(RequestKind::Disconnect, 7, |l| {
            l.push_text(attr::USER_NAME, "bia").unwrap();
        });
        assert_eq!(
            request(&mut s, &b).selector.user_name.as_deref(),
            Some("bia")
        );
        // After the window the entry is gone.
        let c = req(RequestKind::Disconnect, 8, |l| {
            l.push_text(attr::USER_NAME, "ana").unwrap();
        });
        let _ = request(&mut s, &c);
        assert!(matches!(
            s.handle(dac(), &c, NOW, 300_001),
            Ok(Incoming::Request(_))
        ));
    }

    #[test]
    fn rfc_prechecks() {
        let mut s = server();
        // §3: Disconnect with an authorization attribute → 401.
        let r = request(
            &mut s,
            &req(RequestKind::Disconnect, 1, |l| {
                l.push_text(attr::USER_NAME, "ana").unwrap();
                l.push_u32(attr::SESSION_TIMEOUT, 10).unwrap();
            }),
        );
        assert_eq!(r.precheck, Some(ErrorCause::UnsupportedAttribute));
        // Disconnect with Mikrotik-Rate-Limit (a change VSA) → 401.
        let r = request(
            &mut s,
            &req(RequestKind::Disconnect, 2, |l| {
                l.push_text(attr::USER_NAME, "ana").unwrap();
                l.push_vsa(vendor::MIKROTIK, 8, b"1M").unwrap();
            }),
        );
        assert_eq!(r.precheck, Some(ErrorCause::UnsupportedAttribute));
        // No session identification → 402.
        let r = request(
            &mut s,
            &req(RequestKind::Coa, 3, |l| {
                l.push_u32(attr::SESSION_TIMEOUT, 10).unwrap();
            }),
        );
        assert_eq!(r.precheck, Some(ErrorCause::MissingAttribute));
        // Wrong NAS-IP-Address → 403.
        let r = request(
            &mut s,
            &req(RequestKind::Disconnect, 4, |l| {
                l.push_text(attr::USER_NAME, "ana").unwrap();
                l.push_ipv4(attr::NAS_IP_ADDRESS, Ipv4Addr::new(10, 0, 0, 2))
                    .unwrap();
            }),
        );
        assert_eq!(r.precheck, Some(ErrorCause::NasIdentificationMismatch));
        // §3.2 Authorize Only without State → 402; with State → flagged.
        let r = request(
            &mut s,
            &req(RequestKind::Coa, 5, |l| {
                l.push_text(attr::USER_NAME, "ana").unwrap();
                l.push_u32(attr::SERVICE_TYPE, SERVICE_TYPE_AUTHORIZE_ONLY)
                    .unwrap();
            }),
        );
        assert_eq!(r.precheck, Some(ErrorCause::MissingAttribute));
        let r = request(
            &mut s,
            &req(RequestKind::Coa, 6, |l| {
                l.push_text(attr::USER_NAME, "ana").unwrap();
                l.push_u32(attr::SERVICE_TYPE, SERVICE_TYPE_AUTHORIZE_ONLY)
                    .unwrap();
                l.push(attr::STATE, b"st").unwrap();
            }),
        );
        assert!(r.authorize_only);
        assert_eq!(r.precheck, None);
        // The NAS answers NAK 507 with Service-Type and the State echoed.
        let mut extra = AttrList::new();
        extra
            .push_u32(attr::SERVICE_TYPE, SERVICE_TYPE_AUTHORIZE_ONLY)
            .unwrap();
        let nak = s.respond(&r, Outcome::Nak(ErrorCause::RequestInitiated), &extra, NOW);
        let p = Packet::parse(&nak).unwrap();
        assert_eq!(p.code(), Code::CoaNak);
        assert_eq!(p.attr_u32(attr::ERROR_CAUSE), Some(507));
        assert_eq!(p.attr(attr::STATE), Some(&b"st"[..]));
        // A 2xx cannot go in a NAK.
        let nak = s.respond(
            &r,
            Outcome::Nak(ErrorCause::ResidualSessionContextRemoved),
            &AttrList::new(),
            NOW,
        );
        assert_eq!(
            Packet::parse(&nak).unwrap().attr_u32(attr::ERROR_CAUSE),
            Some(404)
        );
        // Accounting counters in a CoA are meaningless → 401.
        let r = request(
            &mut s,
            &req(RequestKind::Coa, 9, |l| {
                l.push_text(attr::USER_NAME, "ana").unwrap();
                l.push_u32(attr::ACCT_INPUT_OCTETS, 1).unwrap();
            }),
        );
        assert_eq!(r.precheck, Some(ErrorCause::UnsupportedAttribute));
    }

    #[test]
    fn residual_disconnect_ack_carries_201() {
        let mut s = server();
        let r = request(
            &mut s,
            &req(RequestKind::Disconnect, 1, |l| {
                l.push_text(attr::ACCT_SESSION_ID, "x").unwrap();
            }),
        );
        let ack = s.respond(&r, Outcome::AckResidualRemoved, &AttrList::new(), NOW);
        let p = Packet::parse(&ack).unwrap();
        assert_eq!(
            (p.code(), p.attr_u32(attr::ERROR_CAUSE)),
            (Code::DisconnectAck, Some(201))
        );
    }

    #[test]
    fn cache_is_bounded() {
        let mut s = DynAuthServer::new(DynAuthConfig {
            max_cache: 2,
            ..server().config().clone()
        });
        for id in 0..2 {
            let _ = request(
                &mut s,
                &req(RequestKind::Disconnect, id, |l| {
                    l.push_text(attr::USER_NAME, "a").unwrap();
                }),
            );
        }
        let third = req(RequestKind::Disconnect, 2, |l| {
            l.push_text(attr::USER_NAME, "a").unwrap();
        });
        assert!(matches!(
            s.handle(dac(), &third, NOW, 0),
            Err(Drop::CacheFull)
        ));
    }
}

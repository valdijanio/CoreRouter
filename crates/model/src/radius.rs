//! `/radius` (G4.3j): the RADIUS servers the router asks, as a system
//! service shared by PPP (G4.3d), IPoE/DHCP (G4.3f), hotspot and login.
//! Names and defaults are RouterOS v7's (`/radius`, `/radius incoming`,
//! `/radius monitor`); the protocol is `corerouter-proto-radius` (G4.3b),
//! driven by the daemon's `radius` service.
//!
//! Besides the configuration, this module holds the types of the AAA API
//! (what a caller asks and what it gets back) and of the status the daemon
//! reports: plain data with serde, so commands, the control channel and MCP
//! show them as they are.

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::types::ItemId;

/// RFC 2865 §3 / IANA.
pub const DEFAULT_AUTH_PORT: u16 = 1812;
/// RFC 2866 §3 / IANA.
pub const DEFAULT_ACCT_PORT: u16 = 1813;
/// RFC 5176 §2.3: where a CoA/Disconnect-Request goes. RouterOS listens on
/// 1700 instead (`/radius incoming port`); the operator picks.
pub const DYNAUTH_PORT: u16 = 3799;
/// RouterOS `/radius incoming port` default.
pub const MIKROTIK_INCOMING_PORT: u16 = 1700;
/// RouterOS `timeout=1100ms`: the initial retransmission time.
pub const DEFAULT_TIMEOUT_MS: u32 = 1100;
pub const TIMEOUT_MS: std::ops::RangeInclusive<u32> = 100..=60_000;
/// RFC 5176 §6.3: Event-Timestamp window (seconds).
pub const DEFAULT_REPLAY_WINDOW: u32 = 300;
pub const REPLAY_WINDOW: std::ops::RangeInclusive<u32> = 10..=3600;
/// Entries in `/radius` (the client's failover set is a 64-bit mask).
pub const MAX_SERVERS: usize = 32;
/// RFC 2865 §3 does not cap the secret; FreeRADIUS reads up to 128 bytes.
pub const MAX_SECRET: usize = 128;
pub const MAX_TEXT: usize = 64;
/// Attributes a caller may add to one request.
pub const MAX_EXTRA_ATTRS: usize = 64;

/// What uses a server (`service=ppp,login`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AaaService {
    Ppp,
    Login,
    Hotspot,
    Wireless,
    Dhcp,
    Ipsec,
    Dot1x,
}

impl AaaService {
    pub const ALL: [Self; 7] = [
        Self::Ppp,
        Self::Login,
        Self::Hotspot,
        Self::Wireless,
        Self::Dhcp,
        Self::Ipsec,
        Self::Dot1x,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ppp => "ppp",
            Self::Login => "login",
            Self::Hotspot => "hotspot",
            Self::Wireless => "wireless",
            Self::Dhcp => "dhcp",
            Self::Ipsec => "ipsec",
            Self::Dot1x => "dot1x",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|v| v.as_str() == s)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    #[default]
    Udp,
    /// RADIUS over TLS (RFC 6614): G4.3ba. Accepted in the config so an
    /// imported RouterOS line keeps its meaning; refused by `radius.add`
    /// until the transport exists.
    Radsec,
}

/// RouterOS `require-message-auth`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RequireMessageAuth {
    /// Accept replies without Message-Authenticator (old servers; open to
    /// Blast-RADIUS, CVE-2024-3596).
    No,
    /// Every Access-Request carries it and every reply must (the default).
    #[default]
    YesForRequestResp,
}

impl RequireMessageAuth {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::No => "no",
            Self::YesForRequestResp => "yes-for-request-resp",
        }
    }
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn main_vrf() -> String {
    "main".into()
}

fn is_main(v: &str) -> bool {
    v == "main"
}

fn auth_port() -> u16 {
    DEFAULT_AUTH_PORT
}

fn acct_port() -> u16 {
    DEFAULT_ACCT_PORT
}

fn timeout() -> u32 {
    DEFAULT_TIMEOUT_MS
}

/// One `/radius` entry. Order matters: it is the failover order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RadiusServer {
    pub id: ItemId,
    pub address: IpAddr,
    /// Who uses it; empty = nobody (RouterOS allows it, the entry is idle).
    pub service: Vec<AaaService>,
    /// Shared secret (RFC 2865 §3). Write-only: commands show `***`.
    pub secret: String,
    #[serde(default = "auth_port")]
    pub authentication_port: u16,
    #[serde(default = "acct_port")]
    pub accounting_port: u16,
    /// Initial retransmission time, ms (then backoff, RFC 5080 §2.2.1).
    #[serde(default = "timeout")]
    pub timeout: u32,
    /// Source address of requests; `None` lets the kernel pick.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_address: Option<IpAddr>,
    #[serde(default = "main_vrf", skip_serializing_if = "is_main")]
    pub vrf: String,
    #[serde(default)]
    pub require_message_auth: RequireMessageAuth,
    #[serde(default)]
    pub protocol: Protocol,
    /// Appended as `@realm` to a User-Name that has none.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub realm: String,
    /// Called-Station-Id when the caller gives none (RouterOS: the PPPoE
    /// service name).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub called_id: String,
    /// Windows domain (MS-CHAP), kept for servers that check it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub domain: String,
    /// Used for accounting only after the non-backup entries.
    #[serde(default, skip_serializing_if = "is_false")]
    pub accounting_backup: bool,
    /// Probe with Status-Server while down (RFC 5997). Off by default: old
    /// servers ignore it and would stay "down" until `dead-time` passes.
    #[serde(default, skip_serializing_if = "is_false")]
    pub status_server: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub comment: String,
}

impl RadiusServer {
    pub fn new(id: ItemId, address: IpAddr) -> Self {
        Self {
            id,
            address,
            service: Vec::new(),
            secret: String::new(),
            authentication_port: DEFAULT_AUTH_PORT,
            accounting_port: DEFAULT_ACCT_PORT,
            timeout: DEFAULT_TIMEOUT_MS,
            src_address: None,
            vrf: main_vrf(),
            require_message_auth: RequireMessageAuth::default(),
            protocol: Protocol::Udp,
            realm: String::new(),
            called_id: String::new(),
            domain: String::new(),
            accounting_backup: false,
            status_server: false,
            disabled: false,
            comment: String::new(),
        }
    }

    pub fn serves(&self, service: AaaService) -> bool {
        !self.disabled && self.service.contains(&service)
    }
}

fn dynauth_port() -> u16 {
    DYNAUTH_PORT
}

fn replay_window() -> u32 {
    DEFAULT_REPLAY_WINDOW
}

/// `/radius incoming`: CoA and Disconnect-Request (RFC 5176) from the
/// servers in `/radius`, each checked with its own secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RadiusIncoming {
    /// Off by default, like RouterOS: a CoA can drop every subscriber.
    pub accept: bool,
    /// 3799 (RFC 5176 §2.3); RouterOS uses 1700.
    #[serde(default = "dynauth_port")]
    pub port: u16,
    #[serde(default = "main_vrf", skip_serializing_if = "is_main")]
    pub vrf: String,
    /// RFC 5176 §6.3 window for Event-Timestamp and the duplicate cache.
    #[serde(default = "replay_window")]
    pub replay_window: u32,
    /// Drop requests without Event-Timestamp (§6.3 "SHOULD be
    /// configurable"). Off: most billing systems do not send it.
    #[serde(skip_serializing_if = "is_false")]
    pub require_event_timestamp: bool,
    /// Drop requests without Message-Authenticator (Blast-RADIUS). Off by
    /// default for the same reason; on when every sender adds it.
    #[serde(skip_serializing_if = "is_false")]
    pub require_message_auth: bool,
}

impl Default for RadiusIncoming {
    fn default() -> Self {
        Self {
            accept: false,
            port: DYNAUTH_PORT,
            vrf: main_vrf(),
            replay_window: DEFAULT_REPLAY_WINDOW,
            require_event_timestamp: false,
            require_message_auth: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Radius {
    pub servers: Vec<RadiusServer>,
    /// Next id handed out (never reused, like RouterOS).
    pub next_id: u32,
    #[serde(skip_serializing_if = "is_default_incoming")]
    pub incoming: RadiusIncoming,
}

fn is_default_incoming(i: &RadiusIncoming) -> bool {
    *i == RadiusIncoming::default()
}

impl Radius {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    pub fn next_id(&mut self) -> ItemId {
        self.next_id = self.next_id.saturating_add(1).max(1);
        ItemId(self.next_id)
    }

    pub fn get(&self, id: ItemId) -> Option<&RadiusServer> {
        self.servers.iter().find(|s| s.id == id)
    }
}

// ---- the AAA API (what callers ask and get) ---------------------------------

/// How the user proved who they are. Secrets never leave the request: the
/// `Debug` of a request hides them.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "method", rename_all = "kebab-case")]
pub enum Credentials {
    /// PAP: hidden per server with its secret (RFC 2865 §5.2).
    Pap { password: String },
    /// CHAP (RFC 1994, RFC 2865 §5.3/§5.40): `response` is the 16-byte
    /// hash, `challenge` what the NAS sent.
    Chap {
        id: u8,
        challenge: Vec<u8>,
        response: Vec<u8>,
    },
    /// MS-CHAPv2 (RFC 2548 §2.3.2): the 50-byte response and the
    /// 16-byte authenticator challenge.
    MsChapV2 {
        ident: u8,
        challenge: Vec<u8>,
        response: Vec<u8>,
    },
    /// No credential (IPoE/DHCP authorizing by MAC or circuit id).
    None,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pap { .. } => "Pap(***)",
            Self::Chap { .. } => "Chap(***)",
            Self::MsChapV2 { .. } => "MsChapV2(***)",
            Self::None => "None",
        })
    }
}

/// One attribute by dictionary name (`Framed-IP-Address`,
/// `Mikrotik-Rate-Limit`), with its value as text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attribute {
    pub name: String,
    pub value: String,
    /// RFC 2868 tag, when the attribute has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<u8>,
}

impl Attribute {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            tag: None,
        }
    }
}

/// An Access-Request, as a caller (PPP, IPoE, login) describes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRequest {
    pub service: AaaService,
    pub user: String,
    pub credentials: Credentials,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nas_port_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nas_port: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calling_station_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub called_station_id: Option<String>,
    /// More attributes, by dictionary name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<Attribute>,
}

impl AuthRequest {
    pub fn pap(service: AaaService, user: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            service,
            user: user.into(),
            credentials: Credentials::Pap {
                password: password.into(),
            },
            nas_port_id: None,
            nas_port: None,
            calling_station_id: None,
            called_station_id: None,
            attributes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthOutcome {
    Accept,
    Reject,
    /// Access-Challenge (not used by PPP; reported as it came).
    Challenge,
    /// No server answered (every one was tried).
    Timeout,
    /// Not sent: no server for the service, bad attribute, overload.
    Error,
}

/// The answer to an [`AuthRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthReply {
    pub outcome: AuthOutcome,
    /// The `/radius` entry that answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<ItemId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_address: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u64>,
    /// Reply attributes decoded through the dictionary (encrypted ones,
    /// like MS-MPPE keys and Tunnel-Password, as `(encrypted, N bytes)`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<Attribute>,
    /// Why, for `error` and `timeout` (and Reply-Message of a reject).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The reply as received, and the authenticator of the request (to
    /// decrypt MPPE keys, RFC 2548 §2.4.2). Not serialized.
    #[serde(skip)]
    pub packet: Vec<u8>,
    #[serde(skip)]
    pub request_authenticator: [u8; 16],
}

impl AuthReply {
    pub fn failed(outcome: AuthOutcome, message: impl Into<String>) -> Self {
        Self {
            outcome,
            server: None,
            server_address: None,
            rtt_ms: None,
            attributes: Vec::new(),
            message: Some(message.into()),
            packet: Vec::new(),
            request_authenticator: [0; 16],
        }
    }

    /// The first attribute named `name`.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|a| a.name == name)
            .map(|a| a.value.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AcctStatus {
    Start,
    InterimUpdate,
    Stop,
}

/// Session counters for Interim-Update and Stop (64-bit: the service
/// splits them into Octets and Gigawords, RFC 2869 §5.1/§5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AcctCounters {
    pub input_octets: u64,
    pub output_octets: u64,
    pub input_packets: u64,
    pub output_packets: u64,
    pub session_time: u32,
}

/// An Accounting-Request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcctRequest {
    pub service: AaaService,
    pub status: AcctStatus,
    /// Acct-Session-Id: unique per session, the CoA selector too.
    pub session_id: String,
    pub user: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counters: Option<AcctCounters>,
    /// RFC 2866 §5.10 Acct-Terminate-Cause (Stop).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminate_cause: Option<u32>,
    /// Interim interval for this session (Acct-Interim-Interval of the
    /// Access-Accept, RFC 2869 §5.16); `None` = `ppp.aaa interim_update`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interim_secs: Option<u32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attributes: Vec<Attribute>,
}

// ---- CoA / Disconnect, as handed to the owner of the sessions ---------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoaKind {
    Coa,
    Disconnect,
}

/// Which sessions a CoA/Disconnect names (RFC 5176 §3), as text.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct CoaSelector {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acct_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub framed_ip: Option<std::net::Ipv4Addr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nas_port_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calling_station_id: Option<String>,
}

/// A CoA or Disconnect-Request that passed the checks (source, secret,
/// replay window).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoaRequest {
    pub kind: CoaKind,
    pub from: std::net::SocketAddr,
    pub selector: CoaSelector,
    /// Authorization changes (CoA), decoded.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub changes: Vec<Attribute>,
    /// Service-Type Authorize Only (RFC 5176 §3.2).
    #[serde(default, skip_serializing_if = "is_false")]
    pub authorize_only: bool,
    /// The request as received (parse it with proto-radius for more).
    #[serde(skip)]
    pub packet: Vec<u8>,
}

/// What the owner of the sessions did with a [`CoaRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CoaOutcome {
    /// None of its sessions match: the next owner is asked.
    NotMine,
    Ack,
    /// NAK with this Error-Cause (RFC 5176 §3.5).
    Nak(u32),
}

/// RFC 5176 §3.5 Error-Cause "Session Context Not Found".
pub const ERROR_SESSION_CONTEXT_NOT_FOUND: u32 = 503;

// ---- status (filled by the daemon) -------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ServerState {
    /// Answering (or not tried yet).
    #[default]
    Up,
    /// Skipped after failures, until `dead-time` passes.
    Down,
    /// Down, asked with Status-Server until it answers (RFC 5997).
    Probing,
    Disabled,
    /// No service runs it (no daemon, or no service listed).
    Idle,
}

impl ServerState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Down => "down",
            Self::Probing => "probing",
            Self::Disabled => "disabled",
            Self::Idle => "idle",
        }
    }
}

/// `/radius monitor` of one entry: authentication and accounting summed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerMonitor {
    pub id: ItemId,
    pub address: Option<IpAddr>,
    pub state: ServerState,
    pub pending: u64,
    pub requests: u64,
    pub accepts: u64,
    pub rejects: u64,
    pub acct_responses: u64,
    pub resends: u64,
    pub timeouts: u64,
    pub bad_replies: u64,
    pub unsolicited: u64,
    pub last_request_rtt: u64,
    pub sockets: u64,
}

/// `/radius incoming` counters.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct IncomingMonitor {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listening: Option<String>,
    pub requests: u64,
    pub acks: u64,
    pub naks: u64,
    pub dropped: u64,
    pub duplicates: u64,
    /// Session owners registered (PPP, IPoE…).
    pub owners: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RadiusStatus {
    pub servers: Vec<ServerMonitor>,
    pub incoming: IncomingMonitor,
    /// Requests waiting for a reply, all services.
    pub pending: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_follow_routeros_and_the_rfc() {
        let s = RadiusServer::new(ItemId(1), "10.0.0.1".parse().unwrap());
        assert_eq!((s.authentication_port, s.accounting_port, s.timeout), (1812, 1813, 1100));
        assert_eq!(s.require_message_auth, RequireMessageAuth::YesForRequestResp);
        let i = RadiusIncoming::default();
        assert!(!i.accept);
        assert_eq!(i.port, 3799);
        assert!(Radius::default().is_default());
    }

    #[test]
    fn secrets_stay_out_of_debug() {
        let r = AuthRequest::pap(AaaService::Ppp, "ana", "segredo");
        assert!(!format!("{r:?}").contains("segredo"));
    }

    #[test]
    fn config_round_trips() {
        let mut r = Radius::default();
        let id = r.next_id();
        let mut s = RadiusServer::new(id, "192.0.2.1".parse().unwrap());
        s.service = vec![AaaService::Ppp, AaaService::Login];
        s.secret = "x".into();
        r.servers.push(s);
        let j = serde_json::to_value(&r).unwrap();
        assert_eq!(j["servers"][0]["service"], serde_json::json!(["ppp", "login"]));
        let back: Radius = serde_json::from_value(j).unwrap();
        assert_eq!(back, r);
    }
}

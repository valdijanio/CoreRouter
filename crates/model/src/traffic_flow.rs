//! `/ip traffic-flow` (G4.4b): flow export in IPFIX or NetFlow v9, like
//! RouterOS. The flows come from the kernel's connection tracking (one
//! record per connection and direction, with the addresses and ports
//! before and after NAT) plus RFC 8158 NAT events, sent to up to
//! [`MAX_TARGETS`] collectors, and kept locally for a while (top talkers,
//! CSV export, the batch API another exporter reads).

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::types::{IfName, ItemId};

/// The NetFlow port most collectors listen on (RouterOS `port` default;
/// IPFIX's own, RFC 7011 §10.3.1, is 4739).
pub const DEFAULT_PORT: u16 = 2055;
/// IPFIX over TLS (RFC 7011 §11.2: 4740 for TLS and DTLS).
pub const TLS_PORT: u16 = 4740;
/// Longest PEM text of a target's certificate, key or CA (a chain of 3–4
/// certificates).
pub const MAX_PEM: usize = 16 * 1024;
/// Longest TLS server name (a DNS name, RFC 1035).
pub const MAX_SERVER_NAME: usize = 253;
pub const MAX_TARGETS: usize = 16;
pub const MAX_INTERFACES: usize = 256;
/// Connections followed for the active/inactive timeouts (about 150 bytes
/// each: 40 MB, **estimado**).
pub const DEFAULT_CACHE: u32 = 262_144;
pub const MIN_CACHE: u32 = 1024;
pub const MAX_CACHE: u32 = 4_194_304;
/// RouterOS defaults: 30 min and 15 s.
pub const DEFAULT_ACTIVE: u32 = 1800;
pub const DEFAULT_INACTIVE: u32 = 15;
pub const MAX_TIMEOUT: u32 = 7 * 86_400;
pub const MAX_SAMPLING: u32 = 65_535;
/// Local store: hours and records at most.
pub const DEFAULT_RETENTION_HOURS: u32 = 24;
pub const MAX_RETENTION_HOURS: u32 = 72;
/// About 160 bytes a record in memory: 32 MB (**estimado**).
pub const DEFAULT_RETENTION_RECORDS: u32 = 200_000;
pub const MAX_RETENTION_RECORDS: u32 = 5_000_000;
/// RouterOS `v9-template-refresh` (packets, 20) and `v9-template-timeout`
/// (RouterOS documents no default; RFC 6728 §4.4.2 says 600 s).
pub const DEFAULT_TEMPLATE_REFRESH: u32 = 20;
pub const DEFAULT_TEMPLATE_TIMEOUT: u32 = 600;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TrafficFlow {
    pub enabled: bool,
    /// Only flows that enter or leave through these; empty is all.
    pub interfaces: Vec<IfName>,
    /// Connections followed at most (RouterOS `cache-entries`).
    pub cache_entries: u32,
    /// Seconds (RouterOS `active-flow-timeout`).
    pub active_flow_timeout: u32,
    /// Seconds (`inactive-flow-timeout`).
    pub inactive_flow_timeout: u32,
    /// Flow records for one connection in N (1: every one). NAT events are
    /// never sampled.
    pub sampling_interval: u32,
    /// Flow records (one per connection and direction). Off for a router
    /// that only logs NAT (G4.4j): the CGNAT's blocks and limits then need
    /// no conntrack reading at all.
    pub flows: bool,
    /// RFC 8158 NAT44 session events (create/delete), one per connection:
    /// off by default (RouterOS `nat-events=no`); the port blocks of the
    /// CGNAT in blocks mode are the compact log.
    pub nat_events: bool,
    /// CGNAT port block allocation and release (RFC 8158 §4.6.10, `natEvent`
    /// 16/17), with the pool, the VLAN and the PPPoE login.
    pub nat_port_blocks: bool,
    /// CGNAT limits (RFC 8158 §4.6.5, §4.6.7.3, §4.6.8.3): pool out of
    /// blocks, a subscriber refused for lack of ports, a subscriber above
    /// the alert percentage. Rate-limited (§5.2).
    pub nat_limits: bool,
    /// The destination in NAT events too. Off by default: the source before
    /// and after NAT with the times is the connection log (Marco Civil art.
    /// 13); the destination is application access, which a connection
    /// provider may not keep (art. 14).
    pub nat_events_destination: bool,
    /// Local store (0 hours: off).
    pub retention_hours: u32,
    pub retention_records: u32,
    pub targets: Vec<FlowTarget>,
    pub next_target_id: u32,
}

impl Default for TrafficFlow {
    fn default() -> Self {
        Self {
            enabled: false,
            interfaces: Vec::new(),
            cache_entries: DEFAULT_CACHE,
            active_flow_timeout: DEFAULT_ACTIVE,
            inactive_flow_timeout: DEFAULT_INACTIVE,
            sampling_interval: 1,
            flows: true,
            nat_events: false,
            nat_port_blocks: true,
            nat_limits: true,
            nat_events_destination: false,
            retention_hours: DEFAULT_RETENTION_HOURS,
            retention_records: DEFAULT_RETENTION_RECORDS,
            targets: Vec::new(),
            next_target_id: 0,
        }
    }
}

impl TrafficFlow {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    pub fn next_target_id(&mut self) -> ItemId {
        self.next_target_id = self.next_target_id.saturating_add(1);
        ItemId(self.next_target_id)
    }

    pub fn target(&self, id: ItemId) -> Option<&FlowTarget> {
        self.targets.iter().find(|t| t.id == id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowVersion {
    /// NetFlow v9 (RFC 3954).
    #[serde(rename = "9")]
    V9,
    /// IPFIX (RFC 7011), "NetFlow v10".
    #[default]
    Ipfix,
}

impl FlowVersion {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V9 => "9",
            Self::Ipfix => "ipfix",
        }
    }
}

impl std::str::FromStr for FlowVersion {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "9" | "v9" | "netflow9" => Ok(Self::V9),
            "10" | "ipfix" => Ok(Self::Ipfix),
            "1" | "5" => Err("NetFlow v1 and v5 carry no IPv6 nor NAT fields: use 9 or ipfix".into()),
            _ => Err("must be 9 or ipfix".into()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FlowTransport {
    #[default]
    Udp,
    /// IPFIX over TCP (RFC 7011 §10.4): nothing lost while the collector
    /// is up, a queue while it is not.
    Tcp,
    /// IPFIX over SCTP (RFC 7011 §10.2, the protocol's mandatory
    /// transport): one IPFIX message per SCTP message, congestion control
    /// and reliability like TCP without a byte stream to reframe.
    Sctp,
    /// IPFIX over TLS on TCP (RFC 7011 §11): encrypted and both sides
    /// authenticated by certificate (§11.3), what RFC 8158 §7 asks of NAT
    /// logs.
    Tls,
}

impl FlowTransport {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Sctp => "sctp",
            Self::Tls => "tls",
        }
    }

    /// A connection that carries a byte or message stream (templates once
    /// per connection, RFC 7011 §8.1).
    pub fn is_stream(self) -> bool {
        !matches!(self, Self::Udp)
    }
}

impl std::str::FromStr for FlowTransport {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            "sctp" => Ok(Self::Sctp),
            "tls" => Ok(Self::Tls),
            "dtls" => Err("DTLS is not supported: use tls (IPFIX over TLS on TCP)".into()),
            _ => Err("must be udp, tcp, sctp or tls".into()),
        }
    }
}

/// What a collector receives (G4.4j): a NAT log server needs no traffic
/// flows, a traffic analyzer no NAT events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetRecords {
    #[default]
    All,
    /// NAT events only: sessions, port blocks, limits.
    Nat,
    Flows,
}

impl TargetRecords {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Nat => "nat",
            Self::Flows => "flows",
        }
    }

    pub fn wants_flows(self) -> bool {
        self != Self::Nat
    }

    pub fn wants_nat(self) -> bool {
        self != Self::Flows
    }
}

impl std::str::FromStr for TargetRecords {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "all" => Ok(Self::All),
            "nat" => Ok(Self::Nat),
            "flows" => Ok(Self::Flows),
            _ => Err("must be all, nat or flows".into()),
        }
    }
}

/// A collector (RouterOS `/ip traffic-flow target`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowTarget {
    pub id: ItemId,
    pub dst_address: IpAddr,
    #[serde(default = "default_port")]
    pub port: u16,
    /// Source address of the export packets; the route's when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub src_address: Option<IpAddr>,
    #[serde(default)]
    pub version: FlowVersion,
    #[serde(default)]
    pub transport: FlowTransport,
    /// Templates again after this many packets (UDP; 0: never by count).
    #[serde(default = "default_refresh")]
    pub template_refresh: u32,
    /// … and after this many seconds (UDP; 0: never by time).
    #[serde(default = "default_timeout")]
    pub template_timeout: u32,
    /// What this collector receives (`records` is the status's count).
    #[serde(default, skip_serializing_if = "is_all")]
    pub content: TargetRecords,
    /// `natEvent` 1/2 (Historic, RFC 8158 §4.3) instead of 4/5 for the
    /// NAT44 session events: collectors made for ipt-netflow and older
    /// Juniper and F5 boxes.
    #[serde(default, skip_serializing_if = "is_false")]
    pub nat_events_legacy: bool,
    /// TLS (RFC 7011 §11.3): this router's certificate chain and key (PEM),
    /// which the collector checks (mutual authentication).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub certificate: String,
    /// Secret (`auth::SECRET_KEYS`): never in the journal or the log.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub private_key: String,
    /// The CA that signed the collector's certificate (PEM); empty: the
    /// public roots compiled in.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ca_certificate: String,
    /// The name the collector's certificate must carry (RFC 7011 §11.3
    /// "reference identifier"); empty: its address (an IP SAN).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server_name: String,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub comment: String,
}

fn is_all(r: &TargetRecords) -> bool {
    *r == TargetRecords::All
}

fn is_false(b: &bool) -> bool {
    !*b
}

fn default_port() -> u16 {
    DEFAULT_PORT
}

fn default_refresh() -> u32 {
    DEFAULT_TEMPLATE_REFRESH
}

fn default_timeout() -> u32 {
    DEFAULT_TEMPLATE_TIMEOUT
}

impl FlowTarget {
    pub fn new(id: ItemId, dst_address: IpAddr) -> Self {
        Self {
            id,
            dst_address,
            port: DEFAULT_PORT,
            src_address: None,
            version: FlowVersion::default(),
            transport: FlowTransport::default(),
            template_refresh: DEFAULT_TEMPLATE_REFRESH,
            template_timeout: DEFAULT_TEMPLATE_TIMEOUT,
            content: TargetRecords::All,
            nat_events_legacy: false,
            certificate: String::new(),
            private_key: String::new(),
            ca_certificate: String::new(),
            server_name: String::new(),
            disabled: false,
            comment: String::new(),
        }
    }
}

/// What the exporter is doing (operational, filled by the daemon, never
/// saved; in the session with `ext_mut`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TrafficFlowStatus {
    pub state: FlowState,
    /// `conntrack` (the kernel's events) or `lab`.
    pub source: String,
    pub last_error: Option<String>,
    /// Conntrack events read since the exporter started.
    pub events: u64,
    /// Times the kernel dropped events (socket buffer full, `ENOBUFS`).
    pub kernel_overruns: u64,
    /// Events in the queue between the reader and the exporter, its size,
    /// and those dropped for a full queue.
    pub queue: u64,
    pub queue_size: u64,
    pub queue_dropped: u64,
    /// Connections followed, and those not followed for a full cache.
    pub cache_used: u64,
    pub cache_full: u64,
    pub sampled_out: u64,
    /// Followed connections gone without an end event.
    pub vanished: u64,
    pub flows: u64,
    pub nat_events: u64,
    /// CGNAT block and limit events taken from the engine's queue, and
    /// those it dropped for a full queue (G4.4j).
    #[serde(default)]
    pub nat_log: u64,
    #[serde(default)]
    pub nat_log_dropped: u64,
    /// Records in the last minute.
    pub records_per_min: u64,
    /// Whether the kernel counts bytes (`nf_conntrack_acct`) and stamps
    /// times (`nf_conntrack_timestamp`); `None` when not known.
    pub accounting: Option<bool>,
    pub timestamps: Option<bool>,
    pub targets: Vec<TargetStatus>,
    /// Unix seconds of the last update.
    pub updated: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FlowState {
    /// Off, or no daemon runs the exporter (headless lab, tests).
    #[default]
    Stopped,
    Running,
    /// No event source (`last_error` says why).
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetStatus {
    pub id: ItemId,
    pub state: TargetState,
    pub records: u64,
    pub messages: u64,
    pub bytes: u64,
    pub records_per_min: u64,
    /// Times the templates went out, and the last one (Unix seconds).
    pub template_sends: u64,
    pub last_template: Option<u64>,
    /// Messages waiting (TCP, SCTP, TLS), and those dropped (full queue,
    /// send errors).
    pub queue: u64,
    pub dropped: u64,
    pub send_errors: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetState {
    #[default]
    Disabled,
    Sending,
    /// TCP, SCTP, TLS: not connected (the queue holds what it can).
    Connecting,
    /// The last send failed (`last_error`).
    Error,
}

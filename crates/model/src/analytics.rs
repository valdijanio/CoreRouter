//! `/system analytics` (G4.4f): export to an external ClickHouse that the
//! operator runs. The router keeps nothing long-term here; it batches what
//! it has (metrics, log events, flows, NAT events) and sends it over
//! ClickHouse's HTTP interface. Several routers write to the same database,
//! so every row carries the router's id.
//!
//! This module holds the configuration, the exporter's status (filled by
//! the daemon), the row types other features hand to the exporter (flows
//! and NAT events, G4.4b) and the SQL schema the operator creates once
//! (`docs/analytics.md`, `system.analytics.schema`).

use std::fmt::Write as _;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// Largest PEM block accepted (a certificate chain of 3–4 certificates).
pub const MAX_PEM: usize = 16 * 1024;
pub const MAX_URL: usize = 256;
pub const MAX_NAME: usize = 64;
pub const MAX_PASSWORD: usize = 256;
pub const DEFAULT_DATABASE: &str = "corerouter";
pub const DEFAULT_USER: &str = "default";
/// ClickHouse wants few, large inserts: at least ~1000 rows, about one per
/// second at most (docs: "Selecting an insert strategy").
pub const DEFAULT_BATCH_SIZE: u32 = 10_000;
pub const BATCH_SIZE: std::ops::RangeInclusive<u32> = 100..=1_000_000;
pub const DEFAULT_FLUSH_INTERVAL: u32 = 10;
pub const FLUSH_INTERVAL: std::ops::RangeInclusive<u32> = 1..=3600;
pub const DEFAULT_METRICS_INTERVAL: u32 = 60;
pub const METRICS_INTERVAL: std::ops::RangeInclusive<u32> = 10..=3600;
/// Memory queue, MiB.
pub const DEFAULT_QUEUE_SIZE: u32 = 16;
pub const QUEUE_SIZE: std::ops::RangeInclusive<u32> = 1..=1024;
/// Disk queue, MiB (0: off).
pub const DISK_QUEUE: std::ops::RangeInclusive<u32> = 0..=65_536;

/// How the body of an INSERT is compressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Compression {
    None,
    /// `Content-Encoding: gzip`, which every ClickHouse accepts.
    #[default]
    Gzip,
}

impl Compression {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Gzip => "gzip",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Analytics {
    /// Off until the operator points it at a server.
    pub enabled: bool,
    /// `http(s)://host[:port]` of ClickHouse's HTTP interface (8123, or
    /// 8443 with TLS). Empty until set.
    pub url: String,
    pub database: String,
    pub user: String,
    /// Secret: masked below group `full`, never in the journal or the log.
    pub password: String,
    /// Client certificate (PEM) for ClickHouse's certificate login;
    /// empty: none.
    pub certificate: String,
    /// Its private key (PEM). Secret.
    pub private_key: String,
    /// The CA that signed the server's certificate (PEM), for a server
    /// with its own CA; empty: the public roots compiled in.
    pub ca_certificate: String,
    /// `false` still encrypts but accepts any server certificate.
    pub tls_verify: bool,
    /// The `router` column of every row; empty: the system identity.
    pub router_id: String,
    pub metrics: bool,
    pub logs: bool,
    pub flows: bool,
    pub nat_events: bool,
    /// Seconds between two metric samples.
    pub metrics_interval: u32,
    /// Rows per INSERT at most.
    pub batch_size: u32,
    /// Seconds a row may wait for its batch to fill.
    pub flush_interval: u32,
    /// MiB of rows kept in memory while the server is slow or away.
    pub queue_size: u32,
    /// MiB of rows kept on disk beyond that (needs the daemon's
    /// `--analytics-spool`); 0: off.
    pub disk_queue: u32,
    pub compression: Compression,
}

impl Default for Analytics {
    fn default() -> Self {
        Self {
            enabled: false,
            url: String::new(),
            database: DEFAULT_DATABASE.into(),
            user: DEFAULT_USER.into(),
            password: String::new(),
            certificate: String::new(),
            private_key: String::new(),
            ca_certificate: String::new(),
            tls_verify: true,
            router_id: String::new(),
            metrics: true,
            logs: true,
            flows: true,
            nat_events: true,
            metrics_interval: DEFAULT_METRICS_INTERVAL,
            batch_size: DEFAULT_BATCH_SIZE,
            flush_interval: DEFAULT_FLUSH_INTERVAL,
            queue_size: DEFAULT_QUEUE_SIZE,
            disk_queue: 0,
            compression: Compression::Gzip,
        }
    }
}

impl Analytics {
    pub fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// Whether `table` is to be sent.
    pub fn sends(&self, table: Table) -> bool {
        match table {
            Table::Metrics => self.metrics,
            Table::Logs => self.logs,
            Table::Flows => self.flows,
            Table::NatEvents => self.nat_events,
        }
    }
}

/// The tables of the schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Table {
    Metrics,
    Logs,
    Flows,
    NatEvents,
}

impl Table {
    pub const ALL: [Table; 4] = [Self::Metrics, Self::Logs, Self::Flows, Self::NatEvents];

    pub fn name(self) -> &'static str {
        match self {
            Self::Metrics => "metrics",
            Self::Logs => "logs",
            Self::Flows => "flows",
            Self::NatEvents => "nat_events",
        }
    }

    /// Days a row is kept by the reference schema's TTL: metrics 13 months
    /// (a year back plus the month to compare), logs 90 days, flows 30
    /// days (the heaviest), NAT events 400 days (Marco Civil da Internet,
    /// Lei 12.965/2014 art. 13: connection records for a year, plus margin).
    pub fn default_ttl_days(self) -> u32 {
        match self {
            Self::Metrics => 395,
            Self::Logs => 90,
            Self::Flows => 30,
            Self::NatEvents => 400,
        }
    }
}

/// Per table, what the exporter did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TableCounters {
    /// Rows the server accepted.
    pub sent: u64,
    /// Rows thrown away: the queue was full, or the server refused them
    /// for good (a bad row, a missing table).
    pub dropped: u64,
}

/// `state` of the exporter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AnalyticsState {
    /// Disabled, or no daemon runs the exporter (lab, tests).
    #[default]
    Stopped,
    /// The last INSERT worked.
    Running,
    /// The server is unreachable or answers errors: rows wait in the queue
    /// and the next try comes after a growing pause.
    Retrying,
    /// Enabled but cannot start (a bad certificate, no URL).
    Error,
}

/// `test` of `system.analytics.print`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TestResult {
    /// Asked with `system.analytics.test` (rising number).
    pub requested: u64,
    /// The request the result below belongs to.
    pub done: u64,
    pub ok: bool,
    /// The server's version, or why it failed.
    pub message: String,
    /// Unix time of the result.
    pub at: u64,
    /// Round trip in milliseconds.
    pub ms: u64,
}

/// What the exporter is doing (operational, filled by the daemon, never
/// saved; kept in the session with `ext_mut`).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AnalyticsStatus {
    pub state: AnalyticsState,
    /// The daemon runs an exporter (a test can be asked).
    pub exporter: bool,
    pub sent_rows: u64,
    pub sent_batches: u64,
    /// Bytes on the wire (compressed).
    pub sent_bytes: u64,
    pub queued_rows: u64,
    pub queued_bytes: u64,
    pub disk_rows: u64,
    pub disk_bytes: u64,
    pub dropped_rows: u64,
    pub retries: u64,
    pub tables: std::collections::BTreeMap<String, TableCounters>,
    pub last_error: Option<String>,
    /// Unix time of the last error / the last accepted INSERT.
    pub last_error_at: Option<u64>,
    pub last_sent_at: Option<u64>,
    /// Seconds until the next try while retrying.
    pub retry_in: Option<u64>,
    pub test: TestResult,
}

/// One flow, as an exporter of flows hands it over (G4.4b). Addresses go
/// out as IPv6, IPv4 mapped (`::ffff:a.b.c.d`), like Akvorado does: one
/// column for both families.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowRecord {
    /// Unix milliseconds of the first and last packet.
    pub start_ms: u64,
    pub end_ms: u64,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// IP protocol number (6 TCP, 17 UDP).
    pub proto: u8,
    pub in_if: String,
    pub out_if: String,
    pub bytes: u64,
    pub packets: u64,
    pub tcp_flags: u8,
    /// 1 in N packets sampled (1: every packet).
    pub sampling_rate: u32,
    /// After NAT (RFC 8158 postNATSourceIPv4Address), when translated.
    pub nat_src_addr: Option<IpAddr>,
    pub nat_src_port: Option<u16>,
}

/// One NAT event (RFC 8158 natEvent): a mapping or a port block created or
/// removed, a quota hit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatEvent {
    pub time_ms: u64,
    /// `create`, `delete`, `block_alloc`, `block_release`, `quota_exceeded`…
    pub event: String,
    pub proto: u8,
    /// The subscriber's (inside) address and port.
    pub src_addr: IpAddr,
    pub src_port: u16,
    /// The public (outside) address and port it was translated to.
    pub nat_addr: IpAddr,
    pub nat_port: u16,
    pub dst_addr: Option<IpAddr>,
    pub dst_port: Option<u16>,
    /// Port block of the event (block events), else 0..0.
    pub port_start: u16,
    pub port_end: u16,
}

/// `name` is a ClickHouse identifier the exporter can put in SQL as is.
pub fn valid_identifier(name: &str) -> bool {
    let mut b = name.bytes();
    name.len() <= MAX_NAME
        && b.next().is_some_and(|c| c.is_ascii_alphabetic() || c == b'_')
        && b.all(|c| c.is_ascii_alphanumeric() || c == b'_')
}

/// The schema to create once on the server (`clickhouse-client
/// --multiquery < schema.sql`): one database, the four tables, MergeTree
/// partitioned by day and ordered by (router, time), each with a TTL.
/// `ttl` gives each table's days (`None`: [`Table::default_ttl_days`]).
pub fn schema(database: &str, ttl: impl Fn(Table) -> Option<u32>) -> String {
    let days = |t: Table| ttl(t).unwrap_or_else(|| t.default_ttl_days());
    let mut out = String::new();
    let _ = writeln!(
        out,
        "-- CoreRouter analytics (G4.4f): one database for every router.\n\
         CREATE DATABASE IF NOT EXISTS {database};\n"
    );
    let _ = writeln!(
        out,
        "CREATE TABLE IF NOT EXISTS {database}.metrics
(
    router  LowCardinality(String),
    time    DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    name    LowCardinality(String),
    labels  Map(LowCardinality(String), String),
    value   Float64 CODEC(Gorilla, ZSTD)
)
ENGINE = MergeTree
PARTITION BY toDate(time)
ORDER BY (router, name, time)
TTL toDateTime(time) + INTERVAL {} DAY
SETTINGS ttl_only_drop_parts = 1, non_replicated_deduplication_window = 1000;
",
        days(Table::Metrics)
    );
    let _ = writeln!(
        out,
        "CREATE TABLE IF NOT EXISTS {database}.logs
(
    router           LowCardinality(String),
    time             DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    seq              UInt64,
    severity         LowCardinality(String),
    severity_number  UInt8,
    priority         UInt8,
    topic            LowCardinality(String),
    topics           Array(LowCardinality(String)),
    origin           String,
    message          String CODEC(ZSTD),
    detail           String CODEC(ZSTD)
)
ENGINE = MergeTree
PARTITION BY toDate(time)
ORDER BY (router, time)
TTL toDateTime(time) + INTERVAL {} DAY
SETTINGS ttl_only_drop_parts = 1, non_replicated_deduplication_window = 1000;
",
        days(Table::Logs)
    );
    let _ = writeln!(
        out,
        "CREATE TABLE IF NOT EXISTS {database}.flows
(
    router         LowCardinality(String),
    time           DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    time_start     DateTime64(3, 'UTC'),
    src_addr       IPv6,
    dst_addr       IPv6,
    src_port       UInt16,
    dst_port       UInt16,
    proto          UInt8,
    in_if          LowCardinality(String),
    out_if         LowCardinality(String),
    bytes          UInt64,
    packets        UInt64,
    tcp_flags      UInt8,
    sampling_rate  UInt32,
    nat_src_addr   IPv6,
    nat_src_port   UInt16
)
ENGINE = MergeTree
PARTITION BY toDate(time)
ORDER BY (router, time)
TTL toDateTime(time) + INTERVAL {} DAY
SETTINGS ttl_only_drop_parts = 1, non_replicated_deduplication_window = 1000;
",
        days(Table::Flows)
    );
    let _ = write!(
        out,
        "CREATE TABLE IF NOT EXISTS {database}.nat_events
(
    router      LowCardinality(String),
    time        DateTime64(3, 'UTC') CODEC(Delta, ZSTD),
    event       LowCardinality(String),
    proto       UInt8,
    src_addr    IPv6,
    src_port    UInt16,
    nat_addr    IPv6,
    nat_port    UInt16,
    dst_addr    IPv6,
    dst_port    UInt16,
    port_start  UInt16,
    port_end    UInt16
)
ENGINE = MergeTree
PARTITION BY toDate(time)
ORDER BY (router, time)
TTL toDateTime(time) + INTERVAL {} DAY
SETTINGS ttl_only_drop_parts = 1, non_replicated_deduplication_window = 1000;
",
        days(Table::NatEvents)
    );
    // The same logs under the OpenTelemetry names (`otel_logs` of the
    // collector's ClickHouse exporter), for Grafana's log explorers.
    let _ = write!(
        out,
        "
CREATE VIEW IF NOT EXISTS {database}.otel_logs AS
SELECT
    time                                   AS Timestamp,
    severity                               AS SeverityText,
    severity_number                        AS SeverityNumber,
    'corerouter'                           AS ServiceName,
    message                                AS Body,
    map('host.name', router)               AS ResourceAttributes,
    map('log.topic', topic, 'log.origin', origin, 'log.detail', detail) AS LogAttributes
FROM {database}.logs;
"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_round_trip_and_send_everything_once_enabled() {
        let a: Analytics = serde_json::from_str("{}").unwrap();
        assert!(a.is_default() && !a.enabled && a.tls_verify);
        assert!(Table::ALL.iter().all(|t| a.sends(*t)));
        assert_eq!(a.compression, Compression::Gzip);
    }

    #[test]
    fn identifiers_are_safe_for_sql() {
        assert!(valid_identifier("corerouter"));
        assert!(valid_identifier("_isp_2"));
        for bad in ["", "1db", "a-b", "a.b", "a;DROP", "a b", &"x".repeat(65)] {
            assert!(!valid_identifier(bad), "{bad}");
        }
    }

    #[test]
    fn schema_has_every_table_with_its_ttl() {
        let sql = schema("isp", |t| (t == Table::Logs).then_some(7));
        for t in Table::ALL {
            assert!(sql.contains(&format!("CREATE TABLE IF NOT EXISTS isp.{}\n", t.name())), "{t:?}");
        }
        assert!(sql.contains("INTERVAL 7 DAY"));
        assert!(sql.contains("INTERVAL 400 DAY"));
        assert_eq!(sql.matches("PARTITION BY toDate(time)").count(), 4);
        assert_eq!(sql.matches("ORDER BY (router, ").count(), 4);
        // Retries carry insert_deduplication_token: plain MergeTree needs a window.
        assert_eq!(sql.matches("non_replicated_deduplication_window").count(), 4);
        assert!(sql.contains("CREATE VIEW IF NOT EXISTS isp.otel_logs"));
    }
}

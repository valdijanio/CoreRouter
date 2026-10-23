//! The ClickHouse exporter (G4.4f): sends the router's metrics, log events,
//! flows and NAT events to an external ClickHouse, in batches, over its
//! HTTP interface (`INSERT … FORMAT JSONEachRow`, gzip). The router keeps
//! nothing long-term; the operator's server does (`docs/analytics.md`).
//!
//! One thread, under the supervisor. Every [`TICK`] it copies what is new
//! out of the session lock — log events a rule sends to the `analytics`
//! action, a `system.metrics` sample every `metrics_interval` — takes the
//! flows and NAT events other services handed over ([`submit_flow`],
//! [`submit_nat`]), and sends the batches that are due, without the lock.
//!
//! Failures never block the router: rows wait in a bounded queue
//! (`analytics_queue.rs`: memory, optionally disk) and the next try comes
//! after a pause that doubles up to [`BACKOFF_MAX`], with jitter. What the
//! server answers decides (ClickHouse's HTTP interface; Vector and Fluent
//! Bit do the same):
//!
//! - 2xx: sent;
//! - 400 and other 4xx: the batch itself is bad (a row the server cannot
//!   parse): dropped and counted, so it does not hold the queue forever;
//! - 401, 403, 404 (credentials, missing database or table): kept, retried
//!   — the operator's fix (a password, the schema) lets them through;
//! - 408, 429, 5xx (overload, "too many parts") and network errors: kept,
//!   retried.
//!
//! Every batch carries an `insert_deduplication_token`, so a retry after an
//! answer that was lost is not stored twice (the schema sets
//! `non_replicated_deduplication_window`). Settings the result depends on
//! go in every request, never left to the server's defaults (several
//! changed between ClickHouse versions: `async_insert`,
//! `date_time_input_format`).

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use corerouter_engine::{Shared, lock};
use corerouter_model::analytics::{
    Analytics, AnalyticsState, AnalyticsStatus, Compression, FlowRecord, NatEvent, Table,
};
use rustls::ClientConfig;
use serde_json::json;

use super::analytics_queue::{Limits, Queue};
use super::analytics_rows::{flow_row, log_row, metric_rows, nat_row};
use super::https::{self, Response, Stream, Url};

const TICK: Duration = Duration::from_millis(250);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(20);
/// Sending stops for this tick after this long (the loop has rows to take).
const SEND_BUDGET: Duration = Duration::from_secs(2);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
pub(crate) const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// Flows and NAT events waiting for the exporter's thread at most.
const MAX_INBOX: usize = 200_000;
/// A response body read at most (an error text, a test answer).
const MAX_BODY: usize = 64 * 1024;

/// What other services hand to the exporter.
#[cfg_attr(not(test), allow(dead_code))]
enum Item {
    Flow(FlowRecord),
    Nat(NatEvent),
}

#[derive(Default)]
struct Inbox {
    items: Mutex<Vec<Item>>,
    dropped: AtomicU64,
    /// Bit 0: flows wanted, bit 1: NAT events wanted (the running config).
    wanted: AtomicU64,
}

fn inbox() -> &'static Inbox {
    static INBOX: OnceLock<Inbox> = OnceLock::new();
    INBOX.get_or_init(Inbox::default)
}

fn items(i: &Inbox) -> MutexGuard<'_, Vec<Item>> {
    i.items.lock().unwrap_or_else(|e| e.into_inner())
}

fn submit(item: Item, bit: u64) {
    let i = inbox();
    if i.wanted.load(Ordering::Relaxed) & bit == 0 {
        return;
    }
    let mut v = items(i);
    if v.len() >= MAX_INBOX {
        i.dropped.fetch_add(1, Ordering::Relaxed);
    } else {
        v.push(item);
    }
}

/// A finished flow for the `flows` table (G4.4b calls this). Cheap: a
/// push onto a bounded list; nothing happens unless the exporter is on and
/// sends flows.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn submit_flow(f: FlowRecord) {
    submit(Item::Flow(f), 1);
}

/// A NAT event for the `nat_events` table (G4.4b, CGNAT).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn submit_nat(e: NatEvent) {
    submit(Item::Nat(e), 2);
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// `%`-encoding for a query-string value.
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Where and how to send: built from the config when it changes.
struct Target {
    url: Url,
    tls: Option<Arc<ClientConfig>>,
    user: String,
    password: String,
    cert_auth: bool,
    database: String,
}

impl Target {
    fn new(cfg: &Analytics) -> Result<Self, String> {
        if cfg.url.is_empty() {
            return Err("no url (system.analytics.set url=…)".into());
        }
        let url = Url::parse(&cfg.url)?;
        let cert_auth = !cfg.certificate.is_empty();
        let tls = if url.tls {
            let client = cert_auth.then_some((cfg.certificate.as_str(), cfg.private_key.as_str()));
            Some(https::custom_tls_config(cfg.tls_verify, &cfg.ca_certificate, client)?)
        } else {
            None
        };
        Ok(Self {
            url,
            tls,
            user: cfg.user.clone(),
            password: cfg.password.clone(),
            cert_auth,
            database: cfg.database.clone(),
        })
    }

    /// What the target depends on: a change rebuilds it.
    fn key(cfg: &Analytics) -> String {
        json!([
            cfg.url,
            cfg.user,
            cfg.password,
            cfg.certificate,
            cfg.private_key,
            cfg.ca_certificate,
            cfg.tls_verify,
            cfg.database,
            cfg.compression.as_str()
        ])
        .to_string()
    }

    fn auth_headers(&self) -> Vec<(&'static str, &str)> {
        let mut h = vec![("X-ClickHouse-User", self.user.as_str())];
        if self.cert_auth {
            h.push(("X-ClickHouse-SSL-Certificate-Auth", "on"));
        } else if !self.password.is_empty() {
            h.push(("X-ClickHouse-Key", self.password.as_str()));
        }
        h
    }

    /// The INSERT of one batch into `table`.
    fn insert_path(&self, table: Table, token: u64) -> String {
        let query = format!(
            "INSERT INTO {}.{} FORMAT JSONEachRow",
            self.database,
            table.name()
        );
        format!(
            "/?query={}&async_insert=0&wait_end_of_query=1&input_format_skip_unknown_fields=1\
             &date_time_input_format=basic&insert_deduplication_token={token:016x}",
            encode(&query)
        )
    }
}

/// One connection, kept open between requests.
#[derive(Default)]
struct Conn {
    stream: Option<Stream>,
}

impl Conn {
    fn request(
        &mut self,
        session: &Shared,
        t: &Target,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> Result<Response, String> {
        let url = Url {
            path: path.to_owned(),
            ..t.url.clone()
        };
        // A kept connection the server closed meanwhile fails at once: one
        // more try on a fresh one.
        for fresh in [self.stream.is_none(), true] {
            if fresh {
                self.stream = None;
            }
            let deadline = Instant::now() + REQUEST_TIMEOUT;
            let stream = match self.stream.take() {
                Some(s) => s,
                None => connect(session, t)?,
            };
            let mut stream = stream;
            match https::exchange(&mut stream, method, &url, headers, body, MAX_BODY, deadline) {
                Ok(r) => {
                    if r.keep_alive {
                        self.stream = Some(stream);
                    }
                    return Ok(r);
                }
                Err(e) if fresh => return Err(e),
                Err(_) => {}
            }
        }
        Err("connection lost".into())
    }
}

fn connect(session: &Shared, t: &Target) -> Result<Stream, String> {
    let addrs = if t.url.host == "localhost" {
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
    } else {
        super::dns::resolve(session, &t.url.host)?
    };
    let deadline = Instant::now() + CONNECT_TIMEOUT;
    let mut last = format!("{}: no address", t.url.host);
    for ip in addrs.iter().take(4) {
        match https::connect_with(SocketAddr::new(*ip, t.url.port), t.tls.clone(), &t.url.host, deadline) {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// What the server's answer to an INSERT means.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Sent,
    /// Keep the batch and try again later.
    Retry(String),
    /// The batch is bad: drop it.
    Refused(String),
}

/// The first line of an error body, short.
fn error_text(r: &Response) -> String {
    let body = String::from_utf8_lossy(&r.body);
    let first = body.lines().next().unwrap_or("").trim();
    let first: String = first.chars().take(300).collect();
    let code = r.exception_code.as_deref().map(|c| format!(" (code {c})")).unwrap_or_default();
    format!("HTTP {}{code}: {first}", r.status)
}

pub(crate) fn classify(r: &Response) -> Outcome {
    match r.status {
        200..=299 => Outcome::Sent,
        401 | 403 | 404 | 408 | 429 => Outcome::Retry(error_text(r)),
        400..=499 => Outcome::Refused(error_text(r)),
        _ => Outcome::Retry(error_text(r)),
    }
}

/// The exporter's state, kept across restarts of its thread.
struct Exporter {
    queue: Queue,
    conn: Conn,
    target_key: String,
    target: Option<Result<Target, String>>,
    backoff: Duration,
    next_try: Instant,
    last_metrics: Option<Instant>,
    last_seq: Option<u64>,
    spool: Option<PathBuf>,
    spool_opened: bool,
    status: AnalyticsStatus,
    /// The last error was logged (once per outage, not every try).
    logged: bool,
}

impl Exporter {
    fn new(spool: Option<PathBuf>) -> Self {
        Self {
            queue: Queue::new(Limits::default()),
            conn: Conn::default(),
            target_key: String::new(),
            target: None,
            backoff: Duration::ZERO,
            next_try: Instant::now(),
            last_metrics: None,
            last_seq: None,
            spool,
            spool_opened: false,
            status: AnalyticsStatus::default(),
            logged: false,
        }
    }

    fn fail(&mut self, e: String, now: Instant) {
        self.backoff = (self.backoff * 2).clamp(BACKOFF_MIN, BACKOFF_MAX);
        // Jitter: 75–100 % of the pause, so routers that lost the same
        // server do not come back in step.
        let jitter = u32::try_from(now_ms() % 250).unwrap_or(0) + 750;
        let pause = self.backoff * jitter / 1000;
        self.next_try = now + pause;
        self.status.retries = self.status.retries.saturating_add(1);
        self.status.retry_in = Some(pause.as_secs());
        self.note_error(e);
        if self.status.state != AnalyticsState::Error {
            self.status.state = AnalyticsState::Retrying;
        }
    }

    fn note_error(&mut self, e: String) {
        if !self.logged {
            log::warn!("analytics: {e}");
            self.logged = true;
        }
        self.status.last_error = Some(e);
        self.status.last_error_at = Some(now_ms() / 1000);
    }

    fn ok(&mut self) {
        if self.logged {
            log::info!("analytics: sending again");
            self.logged = false;
        }
        self.backoff = Duration::ZERO;
        self.status.state = AnalyticsState::Running;
        self.status.retry_in = None;
    }

    /// Send what is due, for at most [`SEND_BUDGET`].
    fn send(&mut self, session: &Shared, now: Instant) {
        if now < self.next_try {
            return;
        }
        let start = Instant::now();
        while start.elapsed() < SEND_BUDGET {
            let Some(batch) = self.queue.front() else {
                break;
            };
            let Some(Ok(t)) = &self.target else {
                return;
            };
            let Some(body) = batch.body.clone() else {
                break;
            };
            let path = t.insert_path(batch.table, batch.id);
            let mut headers = t.auth_headers();
            if batch.compression == Compression::Gzip {
                headers.push(("Content-Encoding", "gzip"));
            }
            let r = self.conn.request(session, t, "POST", &path, &headers, &body);
            let outcome = match r {
                Ok(r) => classify(&r),
                Err(e) => Outcome::Retry(e),
            };
            match outcome {
                Outcome::Sent => {
                    self.queue.done(batch.seq, true);
                    self.status.sent_batches = self.status.sent_batches.saturating_add(1);
                    self.status.sent_bytes = self.status.sent_bytes.saturating_add(batch.size);
                    self.status.last_sent_at = Some(now_ms() / 1000);
                    self.ok();
                }
                Outcome::Refused(e) => {
                    self.queue.done(batch.seq, false);
                    let rows = batch.rows;
                    self.note_error(format!("{} rows of {} refused: {e}", rows, batch.table.name()));
                    // The server answered: it is up.
                    self.ok();
                    self.logged = true;
                }
                Outcome::Retry(e) => {
                    self.conn.stream = None;
                    self.fail(format!("{}: {e}", batch.table.name()), Instant::now());
                    return;
                }
            }
        }
    }

    /// `system.analytics.test`: the server's version, and which tables
    /// of the schema exist.
    fn test(&mut self, session: &Shared) -> (bool, String) {
        let t = match &self.target {
            Some(Ok(t)) => t,
            Some(Err(e)) => return (false, e.clone()),
            None => return (false, "no url".into()),
        };
        let query = format!(
            "SELECT concat(version(), '|', arrayStringConcat(arraySort(groupArray(name)), ',')) \
             FROM system.tables WHERE database = '{}' FORMAT TabSeparatedRaw",
            t.database
        );
        let path = format!("/?query={}", encode(&query));
        let headers = t.auth_headers();
        let r = match self.conn.request(session, t, "GET", &path, &headers, &[]) {
            Ok(r) => r,
            Err(e) => {
                self.conn.stream = None;
                return (false, format!("cannot reach {}: {e}", t.url.host));
            }
        };
        if !(200..300).contains(&r.status) {
            return (false, error_text(&r));
        }
        let text = String::from_utf8_lossy(&r.body).trim().to_owned();
        let (version, tables) = text.split_once('|').unwrap_or((text.as_str(), ""));
        let have: Vec<&str> = tables.split(',').collect();
        let missing: Vec<&str> = Table::ALL
            .iter()
            .map(|t| t.name())
            .filter(|n| !have.contains(n))
            .collect();
        let version: String = version.chars().take(32).collect();
        if missing.is_empty() {
            (true, format!("ClickHouse {version}: connected, schema in place"))
        } else {
            (
                false,
                format!(
                    "ClickHouse {version}: connected, but {}.{{{}}} missing: create the schema (system.analytics.schema, docs/analytics.md)",
                    t.database,
                    missing.join(",")
                ),
            )
        }
    }
}

fn limits(cfg: &Analytics) -> Limits {
    Limits {
        batch_rows: u64::from(cfg.batch_size.max(1)),
        flush: Duration::from_secs(u64::from(cfg.flush_interval.max(1))),
        mem_bytes: usize::try_from(cfg.queue_size).unwrap_or(1).saturating_mul(1 << 20),
        disk_bytes: u64::from(cfg.disk_queue).saturating_mul(1 << 20),
        compression: cfg.compression,
    }
}

fn run(session: &Shared, health: &super::Health, ex: &Mutex<Exporter>) {
    let mut ex = ex.lock().unwrap_or_else(|e| e.into_inner());
    while health.sleep(TICK) {
        health.beat();
        tick(session, health, &mut ex);
    }
    ex.queue.persist();
    ex.status.exporter = false;
    publish(session, &ex.status);
}

fn tick(session: &Shared, health: &super::Health, ex: &mut Exporter) {
    let now = Instant::now();
    let (cfg, identity, logging, events, requested) = {
        let s = lock(session);
        let cfg = s.store().running().system.analytics.clone();
        let since = ex.last_seq.unwrap_or_else(|| s.log_seq());
        let events = if cfg.enabled && cfg.logs { s.log_since(since) } else { Vec::new() };
        ex.last_seq = Some(events.last().map_or_else(|| s.log_seq().max(since), |e| e.seq));
        let requested = s.ext::<AnalyticsStatus>().map_or(0, |st| st.test.requested);
        (
            cfg,
            s.store().running().system.identity.clone(),
            s.store().running().system.logging.clone(),
            events,
            requested,
        )
    };
    let wanted = u64::from(cfg.enabled && cfg.flows) | (u64::from(cfg.enabled && cfg.nat_events) << 1);
    inbox().wanted.store(wanted, Ordering::Relaxed);
    let router = if cfg.router_id.is_empty() { identity } else { cfg.router_id.clone() };

    ex.queue.set_limits(limits(&cfg));
    if !ex.spool_opened
        && let Some(dir) = ex.spool.clone()
    {
        ex.spool_opened = true;
        if let Err(e) = ex.queue.open_spool(&dir) {
            log::error!("analytics: disk queue off: {e}");
            ex.status.last_error = Some(format!("disk queue off: {e}"));
        }
    }
    let key = Target::key(&cfg);
    if key != ex.target_key || ex.target.is_none() {
        ex.target_key = key;
        ex.conn = Conn::default();
        ex.backoff = Duration::ZERO;
        ex.next_try = now;
        ex.logged = false;
        ex.target = Some(Target::new(&cfg));
    }
    ex.status.exporter = true;

    if cfg.enabled {
        health.disabled(None);
        let ms = now_ms();
        for ev in &events {
            if let Some(rule) = logging.to_analytics(&ev.topics) {
                ex.queue.push(Table::Logs, &log_row(&router, ev, &rule.prefix, ms), now);
            }
        }
        let every = Duration::from_secs(u64::from(cfg.metrics_interval.max(1)));
        if cfg.metrics && ex.last_metrics.is_none_or(|t| now.saturating_duration_since(t) >= every) {
            ex.last_metrics = Some(now);
            let m = lock(session)
                .execute("system.metrics", &json!({}))
                .unwrap_or(serde_json::Value::Null);
            let text = super::metrics::render(&m, 0.0);
            for row in metric_rows(&router, ms, &text) {
                ex.queue.push(Table::Metrics, &row, now);
            }
        }
        let taken = std::mem::take(&mut *items(inbox()));
        for item in taken {
            match item {
                Item::Flow(f) if cfg.flows => ex.queue.push(Table::Flows, &flow_row(&router, &f), now),
                Item::Nat(e) if cfg.nat_events => ex.queue.push(Table::NatEvents, &nat_row(&router, &e), now),
                _ => {}
            }
        }
        ex.queue.tick(now, false);
        match &ex.target {
            Some(Err(e)) => {
                let e = e.clone();
                ex.status.state = AnalyticsState::Error;
                ex.note_error(e);
            }
            _ => {
                if ex.status.state == AnalyticsState::Error || ex.status.state == AnalyticsState::Stopped {
                    ex.status.state = AnalyticsState::Running;
                }
                ex.send(session, now);
            }
        }
    } else {
        ex.last_metrics = None;
        ex.status.state = AnalyticsState::Stopped;
        ex.status.retry_in = None;
        health.disabled(Some("system.analytics.set enabled=yes url=http://<clickhouse>:8123"));
    }

    if requested > ex.status.test.done {
        let started = Instant::now();
        let (ok, message) = ex.test(session);
        ex.status.test = corerouter_model::analytics::TestResult {
            requested,
            done: requested,
            ok,
            message,
            at: now_ms() / 1000,
            ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
    }

    let q = &ex.queue;
    ex.status.queued_rows = q.queued_rows();
    ex.status.queued_bytes = q.queued_bytes();
    ex.status.disk_rows = q.disk_rows();
    ex.status.disk_bytes = q.disk_bytes();
    let inbox_dropped = inbox().dropped.load(Ordering::Relaxed);
    ex.status.dropped_rows = q.dropped().saturating_add(inbox_dropped);
    ex.status.sent_rows = q.sent();
    ex.status.tables = q
        .counters
        .iter()
        .map(|(t, c)| (t.name().to_owned(), *c))
        .collect();
    if let Some(e) = &q.spool_error {
        ex.status.last_error = Some(e.clone());
    }
    match (&ex.status.state, &ex.status.last_error) {
        (AnalyticsState::Retrying | AnalyticsState::Error, Some(e)) => health.error(e.clone()),
        _ => health.clear_error(),
    }
    publish(session, &ex.status);
}

/// The status into the session; the test request number is the command's.
fn publish(session: &Shared, status: &AnalyticsStatus) {
    let mut s = lock(session);
    if let Some(st) = s.ext_mut::<AnalyticsStatus>() {
        let requested = st.test.requested;
        *st = status.clone();
        st.test.requested = requested.max(status.test.requested);
    }
}

pub(crate) const SERVICE: super::Service = super::Service {
    name: "analytics",
    flags: &[super::Flag {
        name: "--analytics-spool",
        value: Some("<dir>"),
        help: "directory of the ClickHouse exporter's disk queue (system.analytics\ndisk_queue); batches there survive a restart",
    }],
    topic: "system",
    enable: "system.analytics.set enabled=yes",
    depends: &[],
    start,
};

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let session = ctx.session.clone();
    let spool = ctx.flag("--analytics-spool").map(PathBuf::from);
    let ex = Arc::new(Mutex::new(Exporter::new(spool)));
    Ok(Box::new(move |health: &super::Health| {
        run(&session, health, &ex);
        Ok(())
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use corerouter_engine::{Session, shared};
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    /// What the fake ClickHouse saw of one request.
    #[derive(Debug, Clone)]
    pub(crate) struct Seen {
        pub method: String,
        pub path: String,
        pub headers: Vec<(String, String)>,
        pub body: Vec<u8>,
    }

    impl Seen {
        pub(crate) fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        }

        /// The INSERT's rows, gunzipped.
        pub(crate) fn rows(&self) -> Vec<serde_json::Value> {
            let mut text = String::new();
            if self.header("Content-Encoding") == Some("gzip") {
                flate2::read::GzDecoder::new(self.body.as_slice())
                    .read_to_string(&mut text)
                    .unwrap();
            } else {
                text = String::from_utf8(self.body.clone()).unwrap();
            }
            text.lines().map(|l| serde_json::from_str(l).unwrap()).collect()
        }
    }

    /// A fake ClickHouse HTTP server: answers each request with
    /// `answer(&seen)` (status, body) and reports what it saw.
    pub(crate) fn fake_clickhouse(
        answer: impl Fn(&Seen) -> (u16, String) + Send + 'static,
    ) -> (u16, mpsc::Receiver<Seen>) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for conn in l.incoming() {
                let Ok(conn) = conn else { continue };
                let mut r = BufReader::new(conn.try_clone().unwrap());
                let mut w = conn;
                loop {
                    let mut line = String::new();
                    if r.read_line(&mut line).unwrap_or(0) == 0 {
                        break;
                    }
                    let mut parts = line.split_whitespace();
                    let method = parts.next().unwrap_or("").to_owned();
                    let path = parts.next().unwrap_or("").to_owned();
                    let mut headers = Vec::new();
                    let mut len = 0usize;
                    loop {
                        let mut h = String::new();
                        r.read_line(&mut h).unwrap();
                        let h = h.trim_end();
                        if h.is_empty() {
                            break;
                        }
                        if let Some((k, v)) = h.split_once(':') {
                            if k.eq_ignore_ascii_case("content-length") {
                                len = v.trim().parse().unwrap();
                            }
                            headers.push((k.to_owned(), v.trim().to_owned()));
                        }
                    }
                    let mut body = vec![0; len];
                    r.read_exact(&mut body).unwrap();
                    let seen = Seen { method, path, headers, body };
                    let (status, text) = answer(&seen);
                    let _ = tx.send(seen);
                    let code = if status >= 400 { "\r\nX-ClickHouse-Exception-Code: 27" } else { "" };
                    let _ = write!(
                        w,
                        "HTTP/1.1 {status} X\r\nContent-Length: {}{code}\r\nConnection: keep-alive\r\n\r\n{text}",
                        text.len()
                    );
                }
            }
        });
        (port, rx)
    }

    fn query_of(path: &str) -> String {
        let q = path.split("query=").nth(1).unwrap().split('&').next().unwrap();
        let mut out = Vec::new();
        let b = q.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' {
                out.push(u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap(), 16).unwrap());
                i += 3;
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        String::from_utf8(out).unwrap()
    }

    /// The inbox is one for the process: exporter tests take turns.
    fn serial() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn setup(port: u16, extra: serde_json::Value) -> Shared {
        let session = shared(Session::virtual_lab());
        {
            let mut s = lock(&session);
            let mut p = json!({
                "enabled": true, "url": format!("http://127.0.0.1:{port}"),
                "user": "router", "password": "pw", "batch_size": 100, "flush_interval": 1,
                "metrics": false,
            });
            if let (Some(o), Some(e)) = (p.as_object_mut(), extra.as_object()) {
                o.extend(e.clone());
            }
            s.execute("system.analytics.set", &p).unwrap();
            s.execute("system.logging.add", &json!({"topics": ["info"], "action": "analytics", "prefix": "r1"}))
                .unwrap();
        }
        session
    }

    fn run_ticks(session: &Shared, ex: &mut Exporter, n: usize) {
        let h = super::super::Health::new(corerouter_control::Shutdown::default());
        for _ in 0..n {
            tick(session, &h, ex);
            std::thread::sleep(Duration::from_millis(60));
        }
    }

    #[test]
    fn logs_reach_the_server_as_one_gzip_jsoneachrow_insert() {
        let _serial = serial();
        let (port, seen) = fake_clickhouse(|_| (200, String::new()));
        let session = setup(port, json!({}));
        let mut ex = Exporter::new(None);
        run_ticks(&session, &mut ex, 1);
        lock(&session)
            .execute("system.identity.set", &json!({"name": "edge1"}))
            .unwrap();
        // flush_interval 1 s.
        for _ in 0..30 {
            run_ticks(&session, &mut ex, 1);
            if ex.status.sent_rows > 0 {
                break;
            }
        }
        let req = seen.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(req.method, "POST");
        assert_eq!(query_of(&req.path), "INSERT INTO corerouter.logs FORMAT JSONEachRow");
        for s in ["async_insert=0", "wait_end_of_query=1", "insert_deduplication_token=", "date_time_input_format=basic"] {
            assert!(req.path.contains(s), "{s}: {}", req.path);
        }
        assert_eq!(req.header("X-ClickHouse-User"), Some("router"));
        assert_eq!(req.header("X-ClickHouse-Key"), Some("pw"));
        assert_eq!(req.header("Content-Encoding"), Some("gzip"));
        let rows = req.rows();
        let row = rows.iter().find(|r| r["message"].as_str().unwrap().contains("edge1")).unwrap();
        assert_eq!(row["router"], "edge1", "the identity when router_id is empty");
        assert!(row["message"].as_str().unwrap().starts_with("r1 "));
        assert_eq!(row["severity"], "info");
        let st = lock(&session).execute("system.analytics.print", &json!({})).unwrap();
        assert_eq!(st["state"], "running");
        assert!(st["sent_rows"].as_u64().unwrap() >= 1);
        assert_eq!(st["password"], "***");
    }

    #[test]
    fn a_server_error_keeps_the_batch_and_retries_with_the_same_token() {
        let _serial = serial();
        let calls = Arc::new(AtomicU64::new(0));
        let c = calls.clone();
        let (port, seen) = fake_clickhouse(move |_| {
            if c.fetch_add(1, Ordering::SeqCst) == 0 {
                (503, "Code: 252. DB::Exception: Too many parts".into())
            } else {
                (200, String::new())
            }
        });
        let session = setup(port, json!({"router_id": "pop-1"}));
        let mut ex = Exporter::new(None);
        run_ticks(&session, &mut ex, 1);
        lock(&session)
            .execute("system.identity.set", &json!({"name": "x"}))
            .unwrap();
        for _ in 0..80 {
            run_ticks(&session, &mut ex, 1);
            if ex.status.sent_rows > 0 {
                break;
            }
        }
        let first = seen.recv_timeout(Duration::from_secs(5)).unwrap();
        let second = seen.recv_timeout(Duration::from_secs(5)).unwrap();
        let token = |s: &Seen| s.path.split("insert_deduplication_token=").nth(1).unwrap().to_owned();
        assert_eq!(token(&first), token(&second), "a retry is the same batch");
        assert_eq!(second.rows()[0]["router"], "pop-1");
        assert_eq!(ex.status.retries, 1);
        assert!(ex.status.last_error.as_deref().unwrap().contains("503"), "{:?}", ex.status.last_error);
        assert_eq!(ex.status.state, AnalyticsState::Running);
        assert_eq!(ex.status.dropped_rows, 0);
    }

    #[test]
    fn answers_are_classified_like_vector_and_fluent_bit() {
        let r = |status| Response { status, ..Response::default() };
        assert_eq!(classify(&r(200)), Outcome::Sent);
        for s in [401, 403, 404, 408, 429, 500, 503] {
            assert!(matches!(classify(&r(s)), Outcome::Retry(_)), "{s}");
        }
        for s in [400, 413, 422] {
            assert!(matches!(classify(&r(s)), Outcome::Refused(_)), "{s}");
        }
    }

    #[test]
    fn a_bad_batch_is_dropped_and_counted_not_retried_forever() {
        let _serial = serial();
        let (port, _seen) = fake_clickhouse(|_| (400, "Code: 27. DB::Exception: Cannot parse input".into()));
        let session = setup(port, json!({}));
        let mut ex = Exporter::new(None);
        run_ticks(&session, &mut ex, 1);
        lock(&session)
            .execute("system.identity.set", &json!({"name": "y"}))
            .unwrap();
        for _ in 0..30 {
            run_ticks(&session, &mut ex, 1);
            if ex.status.dropped_rows > 0 {
                break;
            }
        }
        assert!(ex.status.dropped_rows >= 1);
        assert_eq!(ex.status.retries, 0);
        assert!(ex.status.last_error.as_deref().unwrap().contains("code 27"), "{:?}", ex.status.last_error);
        assert_eq!(ex.status.tables["logs"].dropped, ex.status.dropped_rows);
    }

    #[test]
    fn the_test_reports_version_and_missing_tables() {
        let _serial = serial();
        let (port, seen) = fake_clickhouse(|s| {
            assert_eq!(s.method, "GET");
            (200, "25.8.1.1|logs,metrics\n".into())
        });
        let session = setup(port, json!({"enabled": false}));
        let mut ex = Exporter::new(None);
        run_ticks(&session, &mut ex, 1);
        lock(&session).execute("system.analytics.test", &json!({})).unwrap();
        run_ticks(&session, &mut ex, 1);
        let q = seen.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(query_of(&q.path).contains("database = 'corerouter'"));
        let st = lock(&session).execute("system.analytics.print", &json!({})).unwrap();
        assert_eq!(st["test"]["done"], 1);
        assert_eq!(st["test"]["ok"], false);
        let msg = st["test"]["message"].as_str().unwrap();
        assert!(msg.contains("25.8.1.1") && msg.contains("flows,nat_events"), "{msg}");
    }

    #[test]
    fn flows_and_nat_events_are_taken_only_when_wanted() {
        let _serial = serial();
        let (port, seen) = fake_clickhouse(|_| (200, String::new()));
        let session = setup(port, json!({"logs": false, "flows": false}));
        let mut ex = Exporter::new(None);
        run_ticks(&session, &mut ex, 1);
        let nat = NatEvent {
            time_ms: 1,
            event: "block_alloc".into(),
            proto: 0,
            src_addr: "100.64.0.1".parse().unwrap(),
            src_port: 0,
            nat_addr: "203.0.113.1".parse().unwrap(),
            nat_port: 0,
            dst_addr: None,
            dst_port: None,
            port_start: 1024,
            port_end: 2047,
        };
        submit_nat(nat);
        submit_flow(FlowRecord {
            start_ms: 0,
            end_ms: 0,
            src_addr: "10.0.0.1".parse().unwrap(),
            dst_addr: "10.0.0.2".parse().unwrap(),
            src_port: 1,
            dst_port: 2,
            proto: 17,
            in_if: String::new(),
            out_if: String::new(),
            bytes: 1,
            packets: 1,
            tcp_flags: 0,
            sampling_rate: 1,
            nat_src_addr: None,
            nat_src_port: None,
        });
        for _ in 0..30 {
            run_ticks(&session, &mut ex, 1);
            if ex.status.tables.get("nat_events").is_some_and(|c| c.sent > 0) {
                break;
            }
        }
        let req = seen.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(query_of(&req.path), "INSERT INTO corerouter.nat_events FORMAT JSONEachRow");
        assert_eq!(req.rows()[0]["nat_addr"], "::ffff:203.0.113.1");
        assert_eq!(inbox().wanted.load(Ordering::Relaxed), 2, "flows off: not even queued");
        assert!(!ex.status.tables.contains_key("flows"));
    }
    /// One statement to a real server, as `default` (the test's admin).
    fn admin_query(url: &str, sql: &str) -> String {
        let t = Target::new(&Analytics { url: url.into(), ..Analytics::default() }).unwrap();
        let session = shared(Session::virtual_lab());
        let mut c = Conn::default();
        let r = c
            .request(&session, &t, "POST", "/", &[("X-ClickHouse-User", "default")], sql.as_bytes())
            .unwrap();
        let body = String::from_utf8_lossy(&r.body).into_owned();
        assert!(r.status == 200, "{sql}: {body}");
        body
    }

    /// Against a real ClickHouse, only when one is given:
    /// `COREROUTER_CLICKHOUSE_URL=http://127.0.0.1:8123` (user `default`
    /// without password creates the schema; `COREROUTER_CLICKHOUSE_USER` /
    /// `_PASSWORD` send). See docs/analytics.md, "Testar com um ClickHouse
    /// de verdade".
    #[test]
    fn real_clickhouse_when_available() {
        let Ok(url) = std::env::var("COREROUTER_CLICKHOUSE_URL") else {
            eprintln!("COREROUTER_CLICKHOUSE_URL not set: skipped");
            return;
        };
        let _serial = serial();
        let db = format!("corerouter_test_{}", std::process::id());
        let sql = corerouter_model::analytics::schema(&db, |_| None);
        for stmt in sql.split(';') {
            let stmt: Vec<&str> = stmt.lines().filter(|l| !l.trim_start().starts_with("--")).collect();
            let stmt = stmt.join("\n");
            if !stmt.trim().is_empty() {
                admin_query(&url, &stmt);
            }
        }
        let user = std::env::var("COREROUTER_CLICKHOUSE_USER").unwrap_or_else(|_| "default".into());
        let password = std::env::var("COREROUTER_CLICKHOUSE_PASSWORD").unwrap_or_default();
        let session = shared(Session::virtual_lab());
        {
            let mut s = lock(&session);
            s.execute(
                "system.analytics.set",
                &json!({"enabled": true, "url": url, "database": db, "user": user, "password": password,
                        "batch_size": 1000, "flush_interval": 1, "router_id": "it-1"}),
            )
            .unwrap();
            s.execute("system.logging.add", &json!({"topics": ["info"], "action": "analytics"}))
                .unwrap();
        }
        let mut ex = Exporter::new(None);
        run_ticks(&session, &mut ex, 1);
        lock(&session).execute("system.identity.set", &json!({"name": "it"})).unwrap();
        submit_nat(NatEvent {
            time_ms: now_ms(),
            event: "block_alloc".into(),
            proto: 6,
            src_addr: "100.64.0.7".parse().unwrap(),
            src_port: 0,
            nat_addr: "203.0.113.9".parse().unwrap(),
            nat_port: 0,
            dst_addr: None,
            dst_port: None,
            port_start: 4096,
            port_end: 6143,
        });
        submit_flow(FlowRecord {
            start_ms: now_ms() - 5000,
            end_ms: now_ms(),
            src_addr: "2001:db8::7".parse().unwrap(),
            dst_addr: "198.51.100.1".parse().unwrap(),
            src_port: 50000,
            dst_port: 443,
            proto: 6,
            in_if: "ether2".into(),
            out_if: "ether1".into(),
            bytes: 9000,
            packets: 7,
            tcp_flags: 0x1b,
            sampling_rate: 1,
            nat_src_addr: None,
            nat_src_port: None,
        });
        for _ in 0..60 {
            run_ticks(&session, &mut ex, 1);
            if ex.status.tables.len() == 4 && ex.status.queued_rows == 0 {
                break;
            }
        }
        assert_eq!(ex.status.dropped_rows, 0, "{:?}", ex.status);
        let count = |t: &str| admin_query(&url, &format!("SELECT count() FROM {db}.{t} WHERE router = 'it-1'")).trim().parse::<u64>().unwrap();
        assert!(count("logs") >= 1);
        assert!(count("metrics") >= 5);
        assert_eq!(count("flows"), 1);
        assert_eq!(count("nat_events"), 1);
        let who = admin_query(&url, &format!("SELECT IPv6NumToString(src_addr), port_start FROM {db}.nat_events FORMAT TSV"));
        assert_eq!(who.trim(), "::ffff:100.64.0.7\t4096");
        let msg = admin_query(&url, &format!("SELECT count() FROM {db}.otel_logs WHERE Body LIKE '%«it»%'"));
        assert_eq!(msg.trim(), "1", "the OTel view reads the same rows");
        // The test command, against the real server.
        lock(&session).execute("system.analytics.test", &json!({})).unwrap();
        run_ticks(&session, &mut ex, 1);
        assert!(ex.status.test.ok, "{:?}", ex.status.test);
        admin_query(&url, &format!("DROP DATABASE {db}"));
    }

    /// TLS against a real ClickHouse: the server checked against our own
    /// CA, login by client certificate (`X-ClickHouse-SSL-Certificate-Auth`).
    /// Only with `COREROUTER_CLICKHOUSE_TLS_URL=https://localhost:8443` and
    /// the PEM files in `COREROUTER_CLICKHOUSE_CA`, `_CERT`, `_KEY`, the
    /// user in `_CERT_USER` (docs/analytics.md).
    #[test]
    fn real_clickhouse_over_tls_with_a_client_certificate() {
        let Ok(url) = std::env::var("COREROUTER_CLICKHOUSE_TLS_URL") else {
            eprintln!("COREROUTER_CLICKHOUSE_TLS_URL not set: skipped");
            return;
        };
        let _serial = serial();
        let read = |k: &str| std::fs::read_to_string(std::env::var(k).unwrap()).unwrap();
        let (ca, cert, key) = (read("COREROUTER_CLICKHOUSE_CA"), read("COREROUTER_CLICKHOUSE_CERT"), read("COREROUTER_CLICKHOUSE_KEY"));
        let user = std::env::var("COREROUTER_CLICKHOUSE_CERT_USER").unwrap();
        let session = shared(Session::virtual_lab());
        lock(&session)
            .execute(
                "system.analytics.set",
                &json!({"url": url, "user": user, "ca_certificate": ca, "certificate": cert, "private_key": key}),
            )
            .unwrap();
        let mut ex = Exporter::new(None);
        run_ticks(&session, &mut ex, 1);
        lock(&session).execute("system.analytics.test", &json!({})).unwrap();
        run_ticks(&session, &mut ex, 1);
        // Connected and logged in: the answer is about the schema, not TLS.
        assert!(ex.status.test.message.starts_with("ClickHouse "), "{:?}", ex.status.test);
        // Another CA: the server is not trusted.
        let other = rcgen::generate_simple_self_signed(vec!["x".to_owned()]).unwrap().cert.pem();
        lock(&session)
            .execute("system.analytics.set", &json!({"ca_certificate": other}))
            .unwrap();
        lock(&session).execute("system.analytics.test", &json!({})).unwrap();
        run_ticks(&session, &mut ex, 1);
        assert!(!ex.status.test.ok);
        assert!(ex.status.test.message.contains("cannot reach"), "{:?}", ex.status.test);
    }

}

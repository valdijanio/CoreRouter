//! `--metrics <addr:port>` (G4.4): the Prometheus text exposition format
//! (version 0.0.4) over plain HTTP, for a Prometheus server or anything
//! that scrapes it (Grafana Agent, VictoriaMetrics, Telegraf).
//!
//! Every scrape runs the `system.metrics` query (tudo é comando: the same
//! numbers reach the CLI and MCP) and [`render`] turns its result into
//! text. Names follow node_exporter's netdev/netclass collectors with the
//! `corerouter_` prefix and an `interface` label, so a node_exporter
//! dashboard needs only the prefix and label renamed.
//!
//! G1.6qd: memory and filesystems as node_exporter's `meminfo` and
//! `filesystem` collectors (`corerouter_memory_MemAvailable_bytes`,
//! `corerouter_filesystem_avail_bytes{mountpoint}`), the router's own
//! processes as the client libraries' `process_*` with a `process` label
//! (summed by name; no `pid` label, which changes on every FRR restart),
//! and the health checks as numbers (0 ok, 1 warning, 2 error).
//!
//! The endpoint has no login, like node_exporter: it binds to 127.0.0.1
//! unless an address is given, and a non-loopback address is logged as a
//! warning. It answers `GET`/`HEAD` of `/metrics` (and a small page at
//! `/`), one connection at a time, with short timeouts and a bounded
//! request, so a slow or hostile client delays a scrape, never the router.

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_control::Shutdown;
use corerouter_engine::{Shared, lock};
use corerouter_model::metrics::{MetricsService, MetricsState, MetricsStatus};
use corerouter_model::service::Listen;
use serde_json::{Value, json};

/// The exposition format's media type (prometheus.io, "Exposition formats").
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
/// Longest request head read; a scrape sends a few hundred bytes.
const MAX_REQUEST: usize = 8 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(2);
/// Longest the whole answer may take to go out: a client that takes a few
/// bytes every few seconds (each `write` making progress) is cut off here,
/// not when it has drained the body at its own pace.
const WRITE_DEADLINE: Duration = Duration::from_secs(10);
/// Bytes per `write`, so the deadline is checked as the answer goes out.
const WRITE_CHUNK: usize = 16 * 1024;
/// Longest label value written (interface names are shorter; a platform
/// link name is not ours to trust).
const MAX_LABEL: usize = 128;

/// Interface counters: (`system.metrics` key, metric name, help).
const IFACE_COUNTERS: &[(&str, &str, &str)] = &[
    (
        "rx_bytes",
        "corerouter_interface_receive_bytes_total",
        "Bytes received (RouterOS rx-byte).",
    ),
    (
        "tx_bytes",
        "corerouter_interface_transmit_bytes_total",
        "Bytes sent (RouterOS tx-byte).",
    ),
    (
        "rx_packets",
        "corerouter_interface_receive_packets_total",
        "Packets received (RouterOS rx-packet).",
    ),
    (
        "tx_packets",
        "corerouter_interface_transmit_packets_total",
        "Packets sent (RouterOS tx-packet).",
    ),
    (
        "rx_errors",
        "corerouter_interface_receive_errs_total",
        "Receive errors (RouterOS rx-error).",
    ),
    (
        "tx_errors",
        "corerouter_interface_transmit_errs_total",
        "Transmit errors (RouterOS tx-error).",
    ),
    (
        "rx_dropped",
        "corerouter_interface_receive_drop_total",
        "Received packets dropped (RouterOS rx-drop).",
    ),
    (
        "tx_dropped",
        "corerouter_interface_transmit_drop_total",
        "Packets dropped before sending (RouterOS tx-drop).",
    ),
    (
        "link_downs",
        "corerouter_interface_link_downs_total",
        "Times the link went down since the daemon started watching (RouterOS link-downs).",
    ),
];

/// The Prometheus text for a `system.metrics` result. Keys that are
/// missing or `null` (a platform that does not count something) produce
/// no sample, never a zero.
pub fn render(m: &Value, scrape_seconds: f64) -> String {
    let mut out = String::with_capacity(4096);
    let ifaces = m
        .get("interfaces")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let name_of = |i: &Value| label(i.get("name").and_then(Value::as_str).unwrap_or(""));

    family(
        &mut out,
        "corerouter_interface_info",
        "gauge",
        "Interfaces the router knows, always 1; type and whether CoreRouter manages it.",
    );
    for i in ifaces {
        let kind = label(i.get("type").and_then(Value::as_str).unwrap_or(""));
        let managed = i.get("managed").and_then(Value::as_bool).unwrap_or(false);
        let _ = writeln!(
            out,
            "corerouter_interface_info{{interface=\"{}\",type=\"{kind}\",managed=\"{managed}\"}} 1",
            name_of(i)
        );
    }
    for (key, metric, help, invert) in [
        (
            "running",
            "corerouter_interface_up",
            "1 when the link is running (carrier and administratively up).",
            false,
        ),
        (
            "disabled",
            "corerouter_interface_admin_up",
            "1 unless the interface is disabled in the config.",
            true,
        ),
    ] {
        family(&mut out, metric, "gauge", help);
        for i in ifaces {
            if let Some(b) = i.get(key).and_then(Value::as_bool) {
                let up = u8::from(b != invert);
                let _ = writeln!(out, "{metric}{{interface=\"{}\"}} {up}", name_of(i));
            }
        }
    }
    for (key, metric, help) in IFACE_COUNTERS {
        family(&mut out, metric, "counter", help);
        for i in ifaces {
            if let Some(v) = i.get(*key).and_then(Value::as_u64) {
                let _ = writeln!(out, "{metric}{{interface=\"{}\"}} {v}", name_of(i));
            }
        }
    }

    let engine = m.get("engine").unwrap_or(&Value::Null);
    let n = |k: &str| engine.get(k).and_then(Value::as_u64);
    family(
        &mut out,
        "corerouter_commands_total",
        "counter",
        "Commands run since start, by kind (change, query, unknown id) and result.",
    );
    for (kind, result, key) in [
        ("change", "ok", "changes_ok"),
        ("change", "error", "changes_failed"),
        ("query", "ok", "queries_ok"),
        ("query", "error", "queries_failed"),
        ("unknown", "error", "unknown"),
    ] {
        if let Some(v) = n(key) {
            let _ = writeln!(
                out,
                "corerouter_commands_total{{kind=\"{kind}\",result=\"{result}\"}} {v}"
            );
        }
    }
    family(
        &mut out,
        "corerouter_commits_total",
        "counter",
        "Commits since start: applied (ok) or refused by validation, lockout or the platform (error).",
    );
    for (result, key) in [("ok", "commits_ok"), ("error", "commits_failed")] {
        if let Some(v) = n(key) {
            let _ = writeln!(out, "corerouter_commits_total{{result=\"{result}\"}} {v}");
        }
    }
    // G0.10: the supervisor's view; a family with no sample is left out.
    let services = m
        .get("services")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    if !services.is_empty() {
        family(
            &mut out,
            "corerouter_service_up",
            "gauge",
            "1 while the daemon service runs (or idles, turned off by the config); 0 while it starts, restarts, is stopped or failed.",
        );
        for v in services {
            let up = v.get("up").and_then(Value::as_bool).unwrap_or(false);
            let _ = writeln!(out, "corerouter_service_up{{name=\"{}\"}} {}", name_of(v), u8::from(up));
        }
        family(
            &mut out,
            "corerouter_service_restarts_total",
            "counter",
            "Restarts of the daemon service after a failure (exit, error or panic) since the daemon started.",
        );
        for v in services {
            if let Some(n) = v.get("restarts").and_then(Value::as_u64) {
                let _ = writeln!(out, "corerouter_service_restarts_total{{name=\"{}\"}} {n}", name_of(v));
            }
        }
    }
    if let Some(d) = m.get("dhcp_server").filter(|d| d.is_object()) {
        dhcp_server(&mut out, d);
    }
    machine(&mut out, m);
    if let Some(v) = m.get("revision").and_then(Value::as_u64) {
        family(
            &mut out,
            "corerouter_config_revision",
            "gauge",
            "Revision of the running config.",
        );
        let _ = writeln!(out, "corerouter_config_revision {v}");
    }
    if let Some(b) = m.get("safe_mode").and_then(Value::as_bool) {
        family(
            &mut out,
            "corerouter_safe_mode",
            "gauge",
            "1 while Safe Mode is active (changes are undone unless confirmed).",
        );
        let _ = writeln!(out, "corerouter_safe_mode {}", u8::from(b));
    }
    family(
        &mut out,
        "corerouter_build_info",
        "gauge",
        "Version of the daemon, always 1.",
    );
    let _ = writeln!(
        out,
        "corerouter_build_info{{version=\"{}\"}} 1",
        label(env!("CARGO_PKG_VERSION"))
    );
    family(
        &mut out,
        "corerouter_scrape_duration_seconds",
        "gauge",
        "Time this scrape took inside the daemon.",
    );
    let _ = writeln!(
        out,
        "corerouter_scrape_duration_seconds {scrape_seconds:.6}"
    );
    out
}

/// G1.6qd: memory, filesystems, the router's processes and the health.
fn machine(out: &mut String, m: &Value) {
    if let Some(mem) = m.get("memory").filter(|v| v.is_object()) {
        for (key, metric, help) in [
            ("total", "corerouter_memory_MemTotal_bytes", "Memory of the machine (MemTotal)."),
            ("available", "corerouter_memory_MemAvailable_bytes", "Memory available for new work without swapping (MemAvailable): alarm on this, not on free."),
            ("free", "corerouter_memory_MemFree_bytes", "Memory not used at all (MemFree)."),
            ("swap_total", "corerouter_memory_SwapTotal_bytes", "Swap space (SwapTotal)."),
            ("swap_free", "corerouter_memory_SwapFree_bytes", "Swap space unused (SwapFree)."),
        ] {
            if let Some(v) = mem.get(key).and_then(Value::as_u64) {
                family(out, metric, "gauge", help);
                let _ = writeln!(out, "{metric} {v}");
            }
        }
    }
    let fss = m.get("filesystems").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
    if !fss.is_empty() {
        for (key, metric, help) in [
            ("total", "corerouter_filesystem_size_bytes", "Size of the filesystem (the image's /config among them)."),
            ("free", "corerouter_filesystem_free_bytes", "Free space, the root's reserve included."),
            ("available", "corerouter_filesystem_avail_bytes", "Space a program can still write (alarm on this)."),
        ] {
            family(out, metric, "gauge", help);
            for f in fss {
                let s = |k: &str| label(f.get(k).and_then(Value::as_str).unwrap_or(""));
                if let Some(v) = f.get(key).and_then(Value::as_u64) {
                    let _ = writeln!(
                        out,
                        "{metric}{{mountpoint=\"{}\",device=\"{}\",fstype=\"{}\"}} {v}",
                        s("mount"),
                        s("device"),
                        s("fs")
                    );
                }
            }
        }
    }
    processes(out, m);
    if let Some(h) = m.get("health").filter(|v| v.is_object()) {
        let level = |s: Option<&str>| match s {
            Some("ok") => Some(0),
            Some("warning") => Some(1),
            Some("error") => Some(2),
            _ => None,
        };
        if let Some(v) = level(h.get("status").and_then(Value::as_str)) {
            family(out, "corerouter_health_status", "gauge", "Worst health check (system.health.check): 0 ok, 1 warning, 2 error.");
            let _ = writeln!(out, "corerouter_health_status {v}");
        }
        let checks = h.get("checks").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
        if !checks.is_empty() {
            family(out, "corerouter_health_check_status", "gauge", "Each health check: 0 ok, 1 warning, 2 error (no sample while unknown).");
            for c in checks {
                if let Some(v) = level(c.get("severity").and_then(Value::as_str)) {
                    let key = label(c.get("key").and_then(Value::as_str).unwrap_or(""));
                    let _ = writeln!(out, "corerouter_health_check_status{{check=\"{key}\"}} {v}");
                }
            }
        }
    }
}

/// The router's own processes, summed by name (two of one name are rare;
/// a pid label would start a new series on every restart).
fn processes(out: &mut String, m: &Value) {
    let list = m.get("processes").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
    if list.is_empty() {
        return;
    }
    #[derive(Default)]
    struct Sum {
        count: u64,
        rss: u64,
        threads: u64,
        fds: Option<u64>,
        cpu: f64,
    }
    let mut by: std::collections::BTreeMap<String, Sum> = std::collections::BTreeMap::new();
    for p in list {
        let e = by.entry(label(p.get("name").and_then(Value::as_str).unwrap_or(""))).or_default();
        let n = |k: &str| p.get(k).and_then(Value::as_u64);
        e.count += 1;
        e.rss += n("rss_bytes").unwrap_or(0);
        e.threads += n("threads").unwrap_or(0);
        if let Some(f) = n("fds") {
            e.fds = Some(e.fds.unwrap_or(0) + f);
        }
        e.cpu += p.get("cpu_seconds").and_then(Value::as_f64).unwrap_or(0.0);
    }
    type Field = fn(&Sum) -> Option<String>;
    let fields: [(&str, &str, &str, Field); 5] = [
        ("corerouter_process_count", "gauge", "Processes of this name running (the daemon, the init, FRR's daemons).", |s| Some(s.count.to_string())),
        ("corerouter_process_resident_memory_bytes", "gauge", "Resident memory (RSS): a steady climb is a leak.", |s| Some(s.rss.to_string())),
        ("corerouter_process_threads", "gauge", "Threads of the process.", |s| Some(s.threads.to_string())),
        ("corerouter_process_open_fds", "gauge", "Open file descriptors (sockets, files): a steady climb is a leak.", |s| s.fds.map(|f| f.to_string())),
        ("corerouter_process_cpu_seconds_total", "counter", "CPU time (user and system) since the process started.", |s| Some(format!("{:.2}", s.cpu))),
    ];
    for (metric, kind, help, get) in fields {
        family(out, metric, kind, help);
        for (name, s) in &by {
            if let Some(v) = get(s) {
                let _ = writeln!(out, "{metric}{{process=\"{name}\"}} {v}");
            }
        }
    }
}

/// G4.2a: the DHCP server's numbers (`ip.dhcp-server.statistics.print`).
fn dhcp_server(out: &mut String, d: &Value) {
    let obj = |k: &str| d.get(k).and_then(Value::as_object);
    if let Some(l) = obj("leases") {
        family(out, "corerouter_dhcp_leases", "gauge", "DHCP server leases by state.");
        for (state, n) in l {
            if let Some(n) = n.as_u64() {
                let _ = writeln!(out, "corerouter_dhcp_leases{{state=\"{}\"}} {n}", label(state));
            }
        }
    }
    let pools = d.get("pools").and_then(Value::as_array).map_or(&[][..], Vec::as_slice);
    if !pools.is_empty() {
        for (metric, key, help) in [
            ("corerouter_dhcp_pool_size", "size", "Addresses in the pool."),
            ("corerouter_dhcp_pool_used", "bound", "Addresses of the pool bound to a client."),
            ("corerouter_dhcp_pool_offered", "offered", "Addresses of the pool on offer."),
        ] {
            family(out, metric, "gauge", help);
            for p in pools {
                let pool = label(p.get("pool").and_then(Value::as_str).unwrap_or(""));
                if let Some(n) = p.get(key).and_then(Value::as_u64) {
                    let _ = writeln!(out, "{metric}{{pool=\"{pool}\"}} {n}");
                }
            }
        }
    }
    for (key, metric, help) in [
        ("received", "corerouter_dhcp_received_total", "DHCP messages received, by type."),
        ("sent", "corerouter_dhcp_sent_total", "DHCP replies sent, by type."),
    ] {
        if let Some(by) = obj(key) {
            family(out, metric, "counter", help);
            for (kind, n) in by {
                if let Some(n) = n.as_u64() {
                    let _ = writeln!(out, "{metric}{{type=\"{}\"}} {n}", label(kind));
                }
            }
        }
    }
    if let Some(drops) = d.get("dropped").and_then(Value::as_array) {
        family(out, "corerouter_dhcp_dropped_total", "counter", "DHCP messages that got no answer, by reason.");
        for x in drops {
            let reason = label(x.get("reason").and_then(Value::as_str).unwrap_or(""));
            if let Some(n) = x.get("count").and_then(Value::as_u64) {
                let _ = writeln!(out, "corerouter_dhcp_dropped_total{{reason=\"{reason}\"}} {n}");
            }
        }
    }
    for (key, metric, kind, help) in [
        ("probes", "corerouter_dhcp_probes_total", "counter", "ARP probes before an offer."),
        ("conflicts", "corerouter_dhcp_conflicts_total", "counter", "Addresses found in use (probe answered, or DECLINE)."),
        ("rogue_replies", "corerouter_dhcp_rogue_replies_total", "counter", "Replies of unknown DHCP servers heard where an alert watches."),
        ("peak_acks", "corerouter_dhcp_peak_acks_per_second", "gauge", "Most ACKs sent in one second since the start or the last reset."),
    ] {
        if let Some(n) = d.get(key).and_then(Value::as_u64) {
            family(out, metric, kind, help);
            let _ = writeln!(out, "{metric} {n}");
        }
    }
    let lat = d.get("latency_us");
    if let Some(buckets) = lat.and_then(|l| l.get("buckets")).and_then(Value::as_array) {
        let name = "corerouter_dhcp_reply_seconds";
        family(out, name, "histogram", "Time from a request's arrival to its reply leaving (an offer's probe wait not counted).");
        for b in buckets {
            let le = match b.get(0).and_then(Value::as_u64) {
                Some(us) => format!("{}", us as f64 / 1e6),
                None => "+Inf".into(),
            };
            let n = b.get(1).and_then(Value::as_u64).unwrap_or(0);
            let _ = writeln!(out, "{name}_bucket{{le=\"{le}\"}} {n}");
        }
        let sum = lat.and_then(|l| l.get("sum")).and_then(Value::as_u64).unwrap_or(0);
        let count = lat.and_then(|l| l.get("count")).and_then(Value::as_u64).unwrap_or(0);
        let _ = writeln!(out, "{name}_sum {}", sum as f64 / 1e6);
        let _ = writeln!(out, "{name}_count {count}");
    }
}

fn family(out: &mut String, name: &str, kind: &str, help: &str) {
    let _ = writeln!(out, "# HELP {name} {help}\n# TYPE {name} {kind}");
}

/// A label value as the format wants it: `\`, `"` and newline escaped,
/// truncated to [`MAX_LABEL`] characters.
pub fn label(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for c in v.chars().take(MAX_LABEL) {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// What a request asks for.
#[derive(Debug, PartialEq, Eq)]
pub enum Route {
    Metrics { head: bool },
    Index { head: bool },
    NotFound,
    MethodNotAllowed,
    Bad,
}

/// Route a request head (only its first line is looked at).
pub fn route(head: &[u8]) -> Route {
    let line = head.split(|b| *b == b'\n').next().unwrap_or_default();
    let Ok(line) = std::str::from_utf8(line) else {
        return Route::Bad;
    };
    let mut parts = line.trim_end_matches('\r').split(' ');
    let (Some(method), Some(target), Some(version)) = (parts.next(), parts.next(), parts.next())
    else {
        return Route::Bad;
    };
    if !version.starts_with("HTTP/1.") || parts.next().is_some() {
        return Route::Bad;
    }
    let head = match method {
        "GET" => false,
        "HEAD" => true,
        _ => return Route::MethodNotAllowed,
    };
    // Prometheus may add a query string (`params` in a scrape config).
    match target.split('?').next() {
        Some("/metrics") => Route::Metrics { head },
        Some("/") => Route::Index { head },
        _ => Route::NotFound,
    }
}

/// Serve scrapes on `listener` until `shutdown` closes (checked between
/// connections; the process exiting ends the thread too).
pub fn spawn(
    listener: TcpListener,
    session: Shared,
    shutdown: Shutdown,
) -> std::io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("metrics".into())
        .spawn(move || {
            for conn in listener.incoming() {
                if shutdown.is_closed() {
                    break;
                }
                match conn {
                    Ok(stream) => {
                        if let Err(e) = serve(stream, &session) {
                            log::debug!("metrics: connection dropped: {e}");
                        }
                    }
                    Err(e) => log::debug!("metrics: accept failed: {e}"),
                }
            }
        })
}

fn serve(mut stream: TcpStream, session: &Shared) -> std::io::Result<()> {
    let head = read_head(&mut stream)?;
    let (status, ctype, body, head_only) = match route(&head) {
        Route::Metrics { head } => (
            "200 OK",
            CONTENT_TYPE,
            scrape(session).into_bytes(),
            head,
        ),
        Route::Index { head } => (
            "200 OK",
            "text/html; charset=utf-8",
            INDEX.as_bytes().to_vec(),
            head,
        ),
        Route::NotFound => (
            "404 Not Found",
            "text/plain",
            b"see /metrics\n".to_vec(),
            false,
        ),
        Route::MethodNotAllowed => (
            "405 Method Not Allowed",
            "text/plain",
            b"GET or HEAD only\n".to_vec(),
            false,
        ),
        Route::Bad => (
            "400 Bad Request",
            "text/plain",
            b"bad request\n".to_vec(),
            false,
        ),
    };
    let allow = if status.starts_with("405") {
        "Allow: GET, HEAD\r\n"
    } else {
        ""
    };
    let deadline = Instant::now() + WRITE_DEADLINE;
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n{allow}\
         Connection: close\r\n\r\n",
        body.len()
    );
    write_by(&mut stream, header.as_bytes(), deadline)?;
    if !head_only {
        write_by(&mut stream, &body, deadline)?;
    }
    stream.flush()
}

/// Write all of `data` before `deadline`, or fail (`TimedOut`).
fn write_by(stream: &mut TcpStream, mut data: &[u8], deadline: Instant) -> std::io::Result<()> {
    while !data.is_empty() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "the client did not take the answer in time",
            ));
        }
        stream.set_write_timeout(Some(left))?;
        let chunk = data.get(..WRITE_CHUNK.min(data.len())).unwrap_or_default();
        let n = stream.write(chunk)?;
        if n == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        data = data.get(n..).unwrap_or_default();
    }
    Ok(())
}

const INDEX: &str = "<!doctype html><title>CoreRouter metrics</title>\
<h1>CoreRouter</h1><p><a href=\"/metrics\">/metrics</a> (Prometheus text format)</p>\n";

/// The request head, up to the blank line, [`MAX_REQUEST`] bytes or
/// [`READ_TIMEOUT`] in all (a client sending a byte a second does not hold
/// the endpoint for longer than one that sends nothing).
fn read_head(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let deadline = Instant::now() + READ_TIMEOUT;
    let mut head = Vec::with_capacity(512);
    let mut buf = [0u8; 1024];
    while head.len() < MAX_REQUEST && !head.windows(4).any(|w| w == b"\r\n\r\n") {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        stream.set_read_timeout(Some(left))?;
        let n = stream.read(&mut buf)?;
        if n == 0 {
            break;
        }
        head.extend_from_slice(buf.get(..n).unwrap_or_default());
    }
    Ok(head)
}

/// One scrape: the query under the session lock (one platform poll, no
/// per-interface query), then the text outside it.
fn scrape(session: &Shared) -> String {
    let start = Instant::now();
    let m = lock(session)
        .execute("system.metrics", &json!({}))
        .unwrap_or_else(|e| {
            log::warn!("metrics: system.metrics failed: {e}");
            Value::Null
        });
    render(&m, start.elapsed().as_secs_f64())
}


/// `--metrics [<addr>:]<port>` (G4.4) and `ip.service.metrics.*` (G4.4c).
pub(crate) const SERVICE: super::Service = super::Service {
    name: "metrics",
    flags: &[super::Flag {
        name: "--metrics",
        value: Some("<a:port>"),
        help: "Prometheus /metrics (interface and engine counters) over plain HTTP,\nno login: a bare port is 127.0.0.1:<port>; e.g. 9100 or [::]:9100\n(outside the config; ip.service.metrics.set is the configured one)",
    }],
    topic: "system",
    enable: "ip.service.metrics.set enabled=yes",
    depends: &[],
    start,
};

/// `--metrics`: a bare port is loopback only; `ADDR:PORT` is explicit.
fn metrics_addr(v: &str) -> Result<SocketAddr, String> {
    if let Ok(port) = v.parse::<u16>() {
        return Ok(SocketAddr::from(([127, 0, 0, 1], port)));
    }
    v.parse().map_err(|_| {
        format!(
            "--metrics: '{}' is not PORT or ADDR:PORT ([::1]:9100 for IPv6)",
            v.chars().take(64).collect::<String>()
        )
    })
}

/// Serve `/metrics` on `--metrics`, if asked for (a bad flag or a busy
/// port stops the daemon, at boot), and on what the config says (the
/// supervised body).
fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
    let flag = match ctx.flag("--metrics") {
        None => None,
        Some(v) => {
            let addr = metrics_addr(v)?;
            let listener = TcpListener::bind(addr)
                .map_err(|e| format!("cannot open --metrics {addr}: {e}"))?;
            let at = listener.local_addr().unwrap_or(addr);
            spawn(listener, ctx.session.clone(), ctx.shutdown.clone())
                .map_err(|e| format!("cannot start the metrics thread: {e}"))?;
            log_open(addr, false);
            Some(at)
        }
    };
    let session = ctx.session.clone();
    Ok(Box::new(move |health: &super::Health| {
        run_service(&session, health, flag);
        Ok(())
    }))
}

fn log_open(addr: SocketAddr, restricted: bool) {
    if addr.ip().is_loopback() {
        log::info!("Prometheus metrics on http://{addr}/metrics (loopback only)");
    } else if restricted {
        log::info!("Prometheus metrics on http://{addr}/metrics (available-from applies)");
    } else {
        log::warn!(
            "Prometheus metrics on http://{addr}/metrics: plain HTTP without login, \
             reachable from the network (set available_from or filter the port)"
        );
    }
}

/// How often the configured service looks at the running config, and the
/// longest a scrape waits to be accepted.
/// G0.30: 50 ms in the unit tests, which follow the config through it.
const TICK: Duration = if cfg!(test) {
    Duration::from_millis(50)
} else {
    Duration::from_secs(1)
};
const ACCEPT_POLL: Duration = Duration::from_millis(20);

/// The service of `ip.service.metrics.*` (G4.4c): one thread that
/// follows the running config. A change closes the listener and opens the
/// new one (a failed bind is retried every tick and reported once in the
/// log and in `last_error`); a client outside `available_from` is
/// disconnected without an answer, as RouterOS `/ip service` does.
#[cfg(test)]
pub fn spawn_service(
    session: Shared,
    shutdown: Shutdown,
) -> std::io::Result<thread::JoinHandle<()>> {
    let health = super::Health::new(shutdown);
    thread::Builder::new()
        .name("metrics-service".into())
        .spawn(move || run_service(&session, &health, None))
}

/// `flag`: where `--metrics` listens (its own thread), for the row.
fn run_service(session: &Shared, health: &super::Health, flag: Option<SocketAddr>) {
    let mut cfg: Option<MetricsService> = None;
    let mut listener: Option<TcpListener> = None;
    let mut status = MetricsStatus::default();
    while !health.stopping() {
        health.beat();
        let mut at: Vec<Listen> = flag.map(|a| Listen::new("http", a)).into_iter().collect();
        if let Some(l) = &listener
            && let Ok(a) = l.local_addr()
        {
            at.push(Listen::new("http", a));
        }
        health.listen(at);
        match &status.last_error {
            Some(e) => health.error(e),
            None => health.clear_error(),
        }
        let now = lock(session).store().running().system.metrics.clone();
        health.disabled((!now.enabled && flag.is_none()).then_some("ip.service.metrics enabled=no"));
        let changed = cfg.as_ref() != Some(&now);
        if changed || (now.enabled && listener.is_none()) {
            if changed {
                listener = None;
                status = MetricsStatus::default();
            }
            if now.enabled {
                let addr = SocketAddr::new(now.address, now.port);
                match open(addr) {
                    Ok(l) => {
                        let at = l.local_addr().unwrap_or(addr);
                        log_open(at, !now.available_from.is_empty());
                        status.status = MetricsState::Listening;
                        status.listening = Some(at.to_string());
                        status.last_error = None;
                        listener = Some(l);
                    }
                    Err(e) => {
                        let e = format!("cannot listen on {addr}: {e}");
                        if status.last_error.as_ref() != Some(&e) {
                            log::error!("metrics service: {e}");
                        }
                        status.status = MetricsState::Error;
                        status.last_error = Some(e);
                    }
                }
            }
            cfg = Some(now.clone());
            publish(session, &status);
        }
        match &listener {
            Some(l) => {
                if accept_for(l, &now, session, &mut status, TICK) {
                    publish(session, &status);
                }
            }
            None => {
                health.sleep(TICK);
            }
        }
    }
    // Stopped: the listener closes with this run.
    publish(session, &MetricsStatus::default());
}

fn open(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let l = TcpListener::bind(addr)?;
    // Non-blocking accept, so the thread sees a config change within a tick.
    l.set_nonblocking(true)?;
    Ok(l)
}

fn publish(session: &Shared, status: &MetricsStatus) {
    if let Some(st) = lock(session).ext_mut::<MetricsStatus>() {
        *st = status.clone();
    }
}

/// Accept and answer connections for `period`; true if any came.
fn accept_for(
    l: &TcpListener,
    cfg: &MetricsService,
    session: &Shared,
    status: &mut MetricsStatus,
    period: Duration,
) -> bool {
    let until = Instant::now() + period;
    let mut any = false;
    while Instant::now() < until {
        match l.accept() {
            Ok((stream, peer)) => {
                any = true;
                if !cfg.allows(peer.ip()) {
                    status.refused = status.refused.saturating_add(1);
                    log::debug!("metrics: {peer} is not in available_from; disconnected");
                    continue;
                }
                status.requests = status.requests.saturating_add(1);
                // The accepted socket may inherit non-blocking mode.
                let served = stream
                    .set_nonblocking(false)
                    .and_then(|()| serve(stream, session));
                if let Err(e) = served {
                    log::debug!("metrics: connection from {peer} dropped: {e}");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
            Err(e) => {
                log::debug!("metrics: accept failed: {e}");
                thread::sleep(ACCEPT_POLL);
            }
        }
    }
    any
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Value {
        json!({
            "revision": 3,
            "mode": "immediate",
            "safe_mode": false,
            "engine": {"changes_ok": 5, "changes_failed": 1, "queries_ok": 9,
                       "queries_failed": 0, "unknown": 2, "commits_ok": 4, "commits_failed": 1},
            "interfaces": [
                {"name": "ether1", "type": "ether", "managed": true, "disabled": false,
                 "running": true, "rx_bytes": 1500, "tx_bytes": 900, "rx_packets": 1,
                 "tx_packets": 1, "rx_errors": 0, "tx_errors": 0, "rx_dropped": 0,
                 "tx_dropped": 0, "link_downs": 2},
                {"name": "vlan10", "type": "vlan", "managed": true, "disabled": true,
                 "running": false, "rx_bytes": null, "tx_bytes": null, "rx_packets": null,
                 "tx_packets": null, "rx_errors": null, "tx_errors": null,
                 "rx_dropped": null, "tx_dropped": null, "link_downs": null},
            ],
            "services": [
                {"name": "dns-server", "state": "running", "up": true, "restarts": 0},
                {"name": "ntp-client", "state": "failed", "up": false, "restarts": 5},
            ],
            "memory": {"total": 4_000_000_000u64, "available": 3_100_000_000u64,
                       "free": 2_000_000_000u64, "swap_total": 0, "swap_free": 0},
            "filesystems": [
                {"mount": "/", "device": "/dev/mapper/root", "fs": "squashfs",
                 "total": 300_000_000, "free": 0, "available": 0},
                {"mount": "/config", "device": "/dev/vda4", "fs": "ext4",
                 "total": 268_435_456, "free": 250_000_000, "available": 236_000_000},
            ],
            "processes": [
                {"name": "corerouter-daemon", "pid": 812, "rss_bytes": 52_428_800,
                 "threads": 31, "fds": 64, "cpu_seconds": 12.5},
                {"name": "bgpd", "pid": 900, "rss_bytes": 20_000_000, "threads": 6,
                 "fds": 20, "cpu_seconds": 1.25},
                {"name": "bgpd", "pid": 901, "rss_bytes": 1_000_000, "threads": 1,
                 "fds": null, "cpu_seconds": 0.25},
                {"name": "zebra", "pid": 902, "rss_bytes": 9_000_000, "threads": 4,
                 "fds": null, "cpu_seconds": 0.5},
            ],
            "health": {"status": "warning", "checks": [
                {"key": "cpu", "severity": "ok"},
                {"key": "disk", "severity": "warning"},
                {"key": "temperature", "severity": "unknown"},
            ]},
        })
    }

    /// G1.6qd: memory, filesystems, processes (summed by name) and health.
    #[test]
    fn renders_memory_disks_processes_and_health() {
        let t = render(&sample(), 0.0);
        for line in [
            "corerouter_memory_MemAvailable_bytes 3100000000",
            "corerouter_memory_MemTotal_bytes 4000000000",
            "corerouter_filesystem_avail_bytes{mountpoint=\"/config\",device=\"/dev/vda4\",fstype=\"ext4\"} 236000000",
            "corerouter_filesystem_size_bytes{mountpoint=\"/\",device=\"/dev/mapper/root\",fstype=\"squashfs\"} 300000000",
            "corerouter_process_resident_memory_bytes{process=\"corerouter-daemon\"} 52428800",
            "corerouter_process_threads{process=\"corerouter-daemon\"} 31",
            "corerouter_process_open_fds{process=\"corerouter-daemon\"} 64",
            "corerouter_process_cpu_seconds_total{process=\"corerouter-daemon\"} 12.50",
            "corerouter_process_count{process=\"bgpd\"} 2",
            "corerouter_process_resident_memory_bytes{process=\"bgpd\"} 21000000",
            "corerouter_process_open_fds{process=\"bgpd\"} 20",
            "corerouter_process_cpu_seconds_total{process=\"bgpd\"} 1.50",
            "corerouter_health_status 1",
            "corerouter_health_check_status{check=\"cpu\"} 0",
            "corerouter_health_check_status{check=\"disk\"} 1",
        ] {
            assert!(t.lines().any(|l| l == line), "no `{line}` in:\n{t}");
        }
        assert!(!t.contains("process=\"zebra\"} 0\n") && !t.contains("open_fds{process=\"zebra\"}"), "unreadable descriptors: no sample");
        assert!(!t.contains("check=\"temperature\""), "unknown: no sample");
        assert!(!t.contains("pid="), "no pid label");
    }

    /// G1.6qd: the lab's `system.metrics` carries the new parts, and they
    /// render.
    #[test]
    fn the_lab_scrape_has_memory_processes_and_health() {
        let mut s = corerouter_engine::Session::virtual_lab();
        let m = s.execute("system.metrics", &json!({})).unwrap();
        assert!(m["memory"]["available"].as_u64().unwrap() > 0, "{m}");
        assert_eq!(m["filesystems"][0]["mount"], "/");
        assert_eq!(m["processes"][0]["name"], "corerouter-daemon");
        assert!(m["health"]["checks"].as_array().unwrap().len() > 3);
        let t = render(&m, 0.0);
        assert!(t.contains("corerouter_process_threads{process=\"bgpd\"} 6"), "{t}");
        assert!(t.contains("corerouter_health_status "));
    }

    #[test]
    fn renders_interface_and_engine_samples() {
        let t = render(&sample(), 0.0012);
        for line in [
            "corerouter_interface_info{interface=\"ether1\",type=\"ether\",managed=\"true\"} 1",
            "corerouter_interface_up{interface=\"ether1\"} 1",
            "corerouter_interface_up{interface=\"vlan10\"} 0",
            "corerouter_interface_admin_up{interface=\"vlan10\"} 0",
            "corerouter_interface_receive_bytes_total{interface=\"ether1\"} 1500",
            "corerouter_interface_transmit_bytes_total{interface=\"ether1\"} 900",
            "corerouter_interface_link_downs_total{interface=\"ether1\"} 2",
            "corerouter_commands_total{kind=\"change\",result=\"error\"} 1",
            "corerouter_commands_total{kind=\"unknown\",result=\"error\"} 2",
            "corerouter_commits_total{result=\"ok\"} 4",
            "corerouter_config_revision 3",
            "corerouter_safe_mode 0",
            "corerouter_service_up{name=\"dns-server\"} 1",
            "corerouter_service_up{name=\"ntp-client\"} 0",
            "corerouter_service_restarts_total{name=\"ntp-client\"} 5",
            "corerouter_scrape_duration_seconds 0.001200",
        ] {
            assert!(t.lines().any(|l| l == line), "no `{line}` in:\n{t}");
        }
        // Not counted by the platform: no sample at all, not a zero.
        assert!(!t.contains("receive_bytes_total{interface=\"vlan10\"}"));
    }

    /// The format's rules (prometheus.io "Exposition formats"): one HELP and
    /// one TYPE per family before its samples, families not interleaved,
    /// names in `[a-zA-Z_:][a-zA-Z0-9_:]*`, `_total` only on counters, and
    /// no sample repeated.
    #[test]
    fn output_follows_the_text_format() {
        let t = render(&sample(), 0.0);
        assert!(t.ends_with('\n'));
        let mut typed: Vec<(String, String)> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for line in t.lines() {
            if let Some(rest) = line.strip_prefix("# TYPE ") {
                let (name, kind) = rest.split_once(' ').unwrap();
                assert!(!typed.iter().any(|(n, _)| n == name), "{name} typed twice");
                assert_eq!(name.ends_with("_total"), kind == "counter", "{name}");
                typed.push((name.into(), kind.into()));
                continue;
            }
            if line.starts_with('#') {
                continue;
            }
            let name = line.split(['{', ' ']).next().unwrap();
            assert!(
                name.chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
                "bad name {name}"
            );
            assert_eq!(
                typed.last().map(|(n, _)| n.as_str()),
                Some(name),
                "sample of {name} outside its family"
            );
            let (series, value) = line.rsplit_once(' ').unwrap();
            assert!(value.parse::<f64>().is_ok(), "value of {line}");
            assert!(seen.insert(series.to_owned()), "{series} twice");
        }
    }

    #[test]
    fn label_values_are_escaped_and_bounded() {
        assert_eq!(label("a\\b\"c\nd"), "a\\\\b\\\"c\\nd");
        assert_eq!(label(&"x".repeat(500)).len(), MAX_LABEL);
        let m = json!({"interfaces": [{"name": "we\"ird\n", "running": true}]});
        assert!(render(&m, 0.0).contains("corerouter_interface_up{interface=\"we\\\"ird\\n\"} 1"));
    }

    #[test]
    fn renders_the_dhcp_server() {
        let m = json!({"dhcp_server": {
            "leases": {"bound": 4, "offered": 1},
            "pools": [{"pool": "lan", "size": 41, "bound": 4, "offered": 1}],
            "received": {"discover": 9}, "sent": {"ack": 4},
            "dropped": [{"reason": "rate-limited", "count": 2}],
            "probes": 5, "conflicts": 1, "rogue_replies": 0, "peak_acks": 3,
            "latency_us": {"sum": 900, "count": 4, "buckets": [[25, 1], [50, 4], [null, 4]]},
        }});
        let text = render(&m, 0.0);
        for want in [
            "corerouter_dhcp_leases{state=\"bound\"} 4",
            "corerouter_dhcp_pool_size{pool=\"lan\"} 41",
            "corerouter_dhcp_received_total{type=\"discover\"} 9",
            "corerouter_dhcp_dropped_total{reason=\"rate-limited\"} 2",
            "corerouter_dhcp_conflicts_total 1",
            "corerouter_dhcp_reply_seconds_bucket{le=\"0.00005\"} 4",
            "corerouter_dhcp_reply_seconds_bucket{le=\"+Inf\"} 4",
            "corerouter_dhcp_reply_seconds_count 4",
        ] {
            assert!(text.contains(want), "{want} not in\n{text}");
        }
    }

    #[test]
    fn nothing_known_still_renders() {
        let t = render(&Value::Null, 0.0);
        assert!(t.contains("corerouter_build_info{version="));
        assert!(!t.contains("corerouter_config_revision"));
    }

    #[test]
    fn routes_requests() {
        let get = |r: &str| route(r.as_bytes());
        assert_eq!(
            get("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"),
            Route::Metrics { head: false }
        );
        assert_eq!(
            get("HEAD /metrics?x=1 HTTP/1.0\r\n\r\n"),
            Route::Metrics { head: true }
        );
        assert_eq!(get("GET / HTTP/1.1\r\n\r\n"), Route::Index { head: false });
        assert_eq!(get("GET /admin HTTP/1.1\r\n\r\n"), Route::NotFound);
        assert_eq!(
            get("POST /metrics HTTP/1.1\r\n\r\n"),
            Route::MethodNotAllowed
        );
        assert_eq!(get("garbage"), Route::Bad);
        assert_eq!(get("GET /metrics SPDY/3\r\n\r\n"), Route::Bad);
        assert_eq!(route(&[0xff, 0xfe, b' ', b'/']), Route::Bad);
        assert_eq!(route(b""), Route::Bad);
    }

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn wait_status(session: &Shared, want: MetricsState, listening: Option<&str>) -> MetricsStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let st = lock(session)
                .ext::<MetricsStatus>()
                .cloned()
                .unwrap_or_default();
            let ok = st.status == want
                && listening.is_none_or(|l| st.listening.as_deref() == Some(l));
            if ok || Instant::now() > deadline {
                return st;
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// The whole answer to `GET /metrics`, or what came before the server
    /// closed the connection.
    fn get_metrics(port: u16) -> std::io::Result<String> {
        let mut c = TcpStream::connect(("127.0.0.1", port))?;
        c.set_read_timeout(Some(Duration::from_secs(5)))?;
        c.write_all(b"GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n")?;
        let mut out = String::new();
        c.read_to_string(&mut out)?;
        Ok(out)
    }

    /// G4.4c: a commit opens, moves and closes the listener; nothing restarts.
    #[test]
    fn the_service_follows_the_running_config() {
        let session = corerouter_engine::shared(corerouter_engine::Session::virtual_lab());
        let shutdown = Shutdown::default();
        spawn_service(session.clone(), shutdown.clone()).unwrap();
        let run = |p: Value| {
            lock(&session)
                .execute("ip.service.metrics.set", &p)
                .unwrap();
        };

        let a = free_port();
        run(json!({"enabled": true, "port": a}));
        let st = wait_status(&session, MetricsState::Listening, Some(&format!("127.0.0.1:{a}")));
        assert_eq!(st.status, MetricsState::Listening, "{st:?}");
        let body = get_metrics(a).unwrap();
        assert!(body.starts_with("HTTP/1.1 200 OK"), "{body}");
        assert!(body.contains("corerouter_interface_up{interface=\"ether1\"}"));
        let g = lock(&session)
            .execute("ip.service.metrics.get", &json!({}))
            .unwrap();
        assert_eq!(g["status"], "listening");

        // Move it: the old port closes, the new one answers.
        let b = free_port();
        run(json!({"port": b}));
        wait_status(&session, MetricsState::Listening, Some(&format!("127.0.0.1:{b}")));
        assert!(get_metrics(b).unwrap().starts_with("HTTP/1.1 200 OK"));
        assert!(get_metrics(a).is_err(), "port {a} still open");

        // Not allowed: disconnected without an answer, and counted.
        run(json!({"available_from": ["192.0.2.0/24"]}));
        let deadline = Instant::now() + Duration::from_secs(10);
        while lock(&session).ext::<MetricsStatus>().is_some_and(|s| s.refused == 0)
            && Instant::now() < deadline
        {
            // The first tries may still reach the listener of the old config.
            let _ = get_metrics(b);
        }
        assert_eq!(get_metrics(b).unwrap_or_default(), "");
        assert!(lock(&session).ext::<MetricsStatus>().unwrap().refused >= 1);

        run(json!({"enabled": false}));
        wait_status(&session, MetricsState::Stopped, None);
        thread::sleep(Duration::from_millis(100));
        assert!(get_metrics(b).is_err(), "disabled but port {b} open");
        shutdown.close();
    }

    #[test]
    fn a_port_in_use_is_an_error_until_it_frees() {
        let session = corerouter_engine::shared(corerouter_engine::Session::virtual_lab());
        let shutdown = Shutdown::default();
        let taken = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = taken.local_addr().unwrap().port();
        spawn_service(session.clone(), shutdown.clone()).unwrap();
        lock(&session)
            .execute("ip.service.metrics.set", &json!({"enabled": true, "port": port}))
            .unwrap();
        let st = wait_status(&session, MetricsState::Error, None);
        assert_eq!(st.status, MetricsState::Error, "{st:?}");
        assert!(st.last_error.unwrap().contains(&port.to_string()));
        drop(taken);
        let st = wait_status(&session, MetricsState::Listening, None);
        assert_eq!(st.status, MetricsState::Listening, "{st:?}");
        shutdown.close();
    }

    /// audit-services #9: a client that drains a byte now and then used to
    /// keep the single-threaded endpoint for as long as it liked (each
    /// `write` made progress within the per-call timeout).
    #[test]
    fn a_slow_reader_is_cut_off_at_the_deadline() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let reader = thread::spawn(move || {
            let mut c = TcpStream::connect(("127.0.0.1", port)).unwrap();
            let mut b = [0u8; 1];
            for _ in 0..40 {
                if c.read(&mut b).unwrap_or(0) == 0 {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
        });
        let (mut stream, _) = l.accept().unwrap();
        let body = vec![b'x'; 64 << 20];
        let start = Instant::now();
        let r = write_by(&mut stream, &body, start + Duration::from_millis(500));
        let took = start.elapsed();
        assert!(r.is_err());
        assert!(took < Duration::from_secs(2), "{took:?}");
        drop(stream);
        reader.join().unwrap();
    }
}

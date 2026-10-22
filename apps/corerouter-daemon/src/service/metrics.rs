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
use serde_json::{Value, json};

/// The exposition format's media type (prometheus.io, "Exposition formats").
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";
/// Longest request head read; a scrape sends a few hundred bytes.
const MAX_REQUEST: usize = 8 * 1024;
const READ_TIMEOUT: Duration = Duration::from_secs(2);
const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
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
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let head = read_head(&mut stream)?;
    let (status, ctype, body, head_only) = match route(&head) {
        Route::Metrics { head } => ("200 OK", CONTENT_TYPE, scrape(session).into_bytes(), head),
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
    write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n{allow}\
         Connection: close\r\n\r\n",
        body.len()
    )?;
    if !head_only {
        stream.write_all(&body)?;
    }
    stream.flush()
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

/// One scrape: the query under the session lock, then the text outside it.
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

/// Serve `/metrics` on `--metrics`, if asked for, and on what the config says.
fn start(ctx: &super::Ctx) -> Result<(), String> {
    if let Err(e) = spawn_service(ctx.session.clone(), ctx.shutdown.clone()) {
        log::error!("metrics service is off: cannot start its thread: {e}");
    }
    let Some(v) = ctx.flag("--metrics") else {
        return Ok(());
    };
    let addr = metrics_addr(v)?;
    let listener =
        TcpListener::bind(addr).map_err(|e| format!("cannot open --metrics {addr}: {e}"))?;
    spawn(listener, ctx.session.clone(), ctx.shutdown.clone())
        .map_err(|e| format!("cannot start the metrics thread: {e}"))?;
    log_open(addr, false);
    Ok(())
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
const TICK: Duration = Duration::from_secs(1);
const ACCEPT_POLL: Duration = Duration::from_millis(20);

/// The service of `ip.service.metrics.*` (G4.4c): one thread that
/// follows the running config. A change closes the listener and opens the
/// new one (a failed bind is retried every tick and reported once in the
/// log and in `last_error`); a client outside `available_from` is
/// disconnected without an answer, as RouterOS `/ip service` does.
pub fn spawn_service(
    session: Shared,
    shutdown: Shutdown,
) -> std::io::Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("metrics-service".into())
        .spawn(move || run_service(&session, &shutdown))
}

fn run_service(session: &Shared, shutdown: &Shutdown) {
    let mut cfg: Option<MetricsService> = None;
    let mut listener: Option<TcpListener> = None;
    let mut status = MetricsStatus::default();
    while !shutdown.is_closed() {
        let now = lock(session).store().running().system.metrics.clone();
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
            None => thread::sleep(TICK),
        }
    }
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
        })
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
}

//! G4.4 end to end: `--metrics` on the real daemon (virtual lab) answers a
//! Prometheus scrape with the text format, and a change made over the
//! control channel shows up in the engine counters.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_control::Client;
use serde_json::{Value, json};

const DAEMON: &str = env!("CARGO_BIN_EXE_corerouter-daemon");

struct Daemon {
    child: Child,
    control: String,
    metrics: String,
    token_file: std::path::PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.token_file);
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn start() -> Daemon {
    let port = free_port();
    let metrics = free_port();
    let token_file =
        std::env::temp_dir().join(format!("cr-metrics-{}-{port}.token", std::process::id()));
    let child = Command::new(DAEMON)
        .args(["--control", &port.to_string()])
        .arg("--token-file")
        .arg(&token_file)
        .arg("--no-discovery")
        .args(["--metrics", &metrics.to_string()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let d = Daemon {
        child,
        control: format!("127.0.0.1:{port}"),
        metrics: format!("127.0.0.1:{metrics}"),
        token_file,
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(&d.metrics).is_err() || !d.token_file.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        thread::sleep(Duration::from_millis(50));
    }
    d
}

/// One raw HTTP exchange: (status line, headers, body).
fn http(addr: &str, request: &str) -> (String, String, String) {
    let mut s = TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    let (head, body) = out.split_once("\r\n\r\n").unwrap();
    let (status, headers) = head.split_once("\r\n").unwrap();
    (status.into(), headers.into(), body.into())
}

fn scrape(d: &Daemon) -> String {
    let (status, headers, body) = http(
        &d.metrics,
        "GET /metrics HTTP/1.1\r\nHost: x\r\nAccept: text/plain\r\n\r\n",
    );
    assert_eq!(status, "HTTP/1.1 200 OK");
    assert!(
        headers.contains("Content-Type: text/plain; version=0.0.4; charset=utf-8"),
        "{headers}"
    );
    body
}

fn sample(body: &str, series: &str) -> u64 {
    body.lines()
        .find_map(|l| l.strip_prefix(series)?.strip_prefix(' '))
        .unwrap_or_else(|| panic!("no {series} in:\n{body}"))
        .parse()
        .unwrap()
}

fn call(d: &Daemon, command: &str, params: Value) -> Value {
    let token = std::fs::read_to_string(&d.token_file).unwrap();
    let mut c = Client::connect(&d.control, Duration::from_secs(2)).unwrap();
    c.set_token(Some(token.trim().to_owned()));
    c.call(
        "engine.execute",
        json!({"command": command, "params": params}),
    )
    .unwrap()
}

#[test]
fn prometheus_scrape_shows_interfaces_and_engine_counters() {
    let d = start();
    let before = scrape(&d);
    assert!(before.contains("# TYPE corerouter_interface_receive_bytes_total counter"));
    for port in 1..=8 {
        let series =
            format!("corerouter_interface_receive_bytes_total{{interface=\"ether{port}\"}}");
        sample(&before, &series);
    }
    let ok = "corerouter_commands_total{kind=\"change\",result=\"ok\"}";
    let commits = "corerouter_commits_total{result=\"ok\"}";

    call(
        &d,
        "ip.address.add",
        json!({"address": "10.9.0.1/24", "interface": "ether2"}),
    );
    let after = scrape(&d);
    assert_eq!(sample(&after, ok), sample(&before, ok) + 1);
    assert_eq!(sample(&after, commits), sample(&before, commits) + 1);
    assert!(
        sample(&after, "corerouter_config_revision")
            > sample(&before, "corerouter_config_revision")
    );
}

#[test]
fn only_get_and_head_of_known_paths() {
    let d = start();
    let (status, headers, body) = http(&d.metrics, "HEAD /metrics HTTP/1.1\r\n\r\n");
    assert_eq!(status, "HTTP/1.1 200 OK");
    assert!(headers.contains("Content-Length: "));
    assert!(body.is_empty());
    let (status, headers, _) = http(&d.metrics, "POST /metrics HTTP/1.1\r\n\r\n");
    assert_eq!(status, "HTTP/1.1 405 Method Not Allowed");
    assert!(headers.contains("Allow: GET, HEAD"));
    let (status, _, _) = http(&d.metrics, "GET /etc/passwd HTTP/1.1\r\n\r\n");
    assert_eq!(status, "HTTP/1.1 404 Not Found");
    let (status, _, body) = http(&d.metrics, "GET / HTTP/1.1\r\n\r\n");
    assert_eq!(status, "HTTP/1.1 200 OK");
    assert!(body.contains("/metrics"));
    // A request that never ends is cut at the size bound, and the next
    // scrape still works.
    let mut s = TcpStream::connect(&d.metrics).unwrap();
    let _ = s.write_all(&vec![b'A'; 64 * 1024]);
    drop(s);
    scrape(&d);
}

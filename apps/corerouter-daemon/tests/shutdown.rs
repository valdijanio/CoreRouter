//! G5.5: a daemon stopped with SIGTERM (`kill`) or SIGINT (Ctrl+C) says
//! goodbye, so the other lab drops it from `ip.neighbor.list` at once
//! instead of after the hold time, and exits with code 0.
//!
//! Two virtual labs on this host (CRDP over loopback, G5.4), each test on
//! its own free UDP port: no namespace, no root, and nothing heard from or
//! sent to other CoreRouter processes on this machine.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Read;
use std::net::{TcpListener, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_control::Client;
use serde_json::{Value, json};

const DAEMON: &str = env!("CARGO_BIN_EXE_corerouter-daemon");

/// Kills the process if the test fails before it exits on its own.
struct Daemon {
    child: Child,
    control: String,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn free_tcp_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn free_udp_port() -> u16 {
    UdpSocket::bind("0.0.0.0:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn call(d: &Daemon, command: &str, params: Value) -> Result<Value, String> {
    Client::connect(&d.control, Duration::from_millis(500)).and_then(|mut c| {
        c.call(
            "engine.execute",
            json!({"command": command, "params": params}),
        )
    })
}

fn wait_for(what: &str, within: Duration, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if ok() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("timed out ({within:?}) waiting for {what}");
}

/// A virtual lab announcing every second on its factory-default ether1.
fn lab(identity: &str, discovery_port: u16) -> Daemon {
    let port = free_tcp_port();
    let child = Command::new(DAEMON)
        .args(["--control", &port.to_string()])
        .args(["--discovery-port", &discovery_port.to_string()])
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let d = Daemon {
        child,
        control: format!("127.0.0.1:{port}"),
    };
    wait_for("the control port", Duration::from_secs(20), || {
        call(&d, "system.identity.set", json!({ "name": identity })).is_ok()
    });
    call(
        &d,
        "ip.neighbor.discovery.set",
        json!({ "interval_secs": 1 }),
    )
    .unwrap();
    d
}

/// Strict: a router that does not answer is a failure, not "forgotten".
fn sees(d: &Daemon, identity: &str) -> bool {
    match call(d, "ip.neighbor.list", json!({})) {
        Ok(Value::Array(rows)) => rows.iter().any(|r| r["identity"] == identity),
        other => panic!("ip.neighbor.list on {}: {other:?}", d.control),
    }
}

fn goodbye_on(signal: &str) {
    let port = free_udp_port();
    let a = lab(&format!("a-{signal}"), port);
    let mut b = lab(&format!("b-{signal}"), port);
    let b_name = format!("b-{signal}");
    wait_for(
        "the labs to see each other",
        Duration::from_secs(10),
        || sees(&a, &b_name) && sees(&b, &format!("a-{signal}")),
    );
    // Still listed a moment later: only the goodbye removes it early.
    thread::sleep(Duration::from_millis(1500));
    assert!(sees(&a, &b_name));

    let status = Command::new("kill")
        .args([&format!("-{signal}"), &b.child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let sent = Instant::now();
    // The hold is 4 s here: gone well before it means the goodbye arrived.
    wait_for("A to forget B", Duration::from_secs(2), || {
        !sees(&a, &b_name)
    });
    let forgotten = sent.elapsed();

    let code = loop {
        if let Some(s) = b.child.try_wait().unwrap() {
            break s;
        }
        assert!(sent.elapsed() < Duration::from_secs(5), "B did not exit");
        thread::sleep(Duration::from_millis(20));
    };
    let mut log = String::new();
    b.child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut log)
        .unwrap();
    assert_eq!(code.code(), Some(0), "SIG{signal}: {code}\n{log}");
    assert!(
        log.contains("shutting down: sent CRDP goodbye on 1 interface(s)"),
        "{log}"
    );
    eprintln!("{log}");
    eprintln!(
        "SIG{signal}: forgotten after {forgotten:?}, exit after {:?}",
        sent.elapsed()
    );
    // A is still fine.
    assert!(call(&a, "interface.list", json!({})).is_ok());
}

#[test]
fn sigterm_says_goodbye_and_exits_0() {
    goodbye_on("TERM");
}

#[test]
fn sigint_says_goodbye_and_exits_0() {
    goodbye_on("INT");
}

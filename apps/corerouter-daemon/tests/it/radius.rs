//! G4.3j end to end: the real daemon (virtual lab) asks a RADIUS server on
//! 127.0.0.1 — `proto-radius`'s test server in a thread, no root — through
//! its `radius` service: `radius.test` over the control channel answers
//! with the reply decoded, `radius.monitor` counts it, and `/radius
//! incoming` answers a CoA with NAK 503 while no session owner (PPP,
//! G4.3d) is registered.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_control::Client;
use corerouter_proto_radius::dynauth::{self, RequestKind};
use corerouter_proto_radius::packet::{AttrList, Code, Packet, PushAttr, attr};
use corerouter_proto_radius::testserver::TestServer;
use serde_json::{Value, json};

const DAEMON: &str = env!("CARGO_BIN_EXE_corerouter-daemon");
const SECRET: &str = "e2e-secret";

struct Daemon {
    child: Child,
    control: String,
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
    let token_file =
        std::env::temp_dir().join(format!("cr-radius-{}-{port}.token", std::process::id()));
    let child = Command::new(DAEMON)
        .args(["--control", &port.to_string()])
        .arg("--token-file")
        .arg(&token_file)
        .arg("--no-discovery")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let d = Daemon {
        child,
        control: format!("127.0.0.1:{port}"),
        token_file,
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while TcpStream::connect(&d.control).is_err() || !d.token_file.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        thread::sleep(Duration::from_millis(50));
    }
    d
}

fn call(d: &Daemon, command: &str, params: Value) -> Result<Value, String> {
    let token = std::fs::read_to_string(&d.token_file).unwrap();
    let mut c = Client::connect(&d.control, Duration::from_secs(2)).unwrap();
    c.set_token(Some(token.trim().to_owned()));
    c.call(
        "engine.execute",
        json!({"command": command, "params": params}),
    )
}

/// The test server on one UDP port, in a thread.
fn radius_server(stop: Arc<AtomicBool>) -> (u16, Arc<Mutex<TestServer>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(5)))
        .unwrap();
    let port = sock.local_addr().unwrap().port();
    let mut s = TestServer::new(SECRET.as_bytes(), 9);
    let mut reply = AttrList::new();
    reply.push_vsa(14988, 8, b"50M/100M").unwrap();
    reply.push_u32(attr::SESSION_TIMEOUT, 86_400).unwrap();
    s.add_user("cliente1", "senha1", reply);
    let srv = Arc::new(Mutex::new(s));
    let shared = srv.clone();
    thread::spawn(move || {
        let t0 = Instant::now();
        let mut buf = [0u8; 4096];
        while !stop.load(Ordering::Relaxed) {
            let Ok((n, from)) = sock.recv_from(&mut buf) else {
                continue;
            };
            let now = t0.elapsed().as_millis() as u64;
            if let Some(r) = shared.lock().unwrap().handle(from, &buf[..n], now) {
                let _ = sock.send_to(&r.bytes, r.to);
            }
        }
    });
    (port, srv)
}

fn until_done(d: &Daemon, id: &Value) -> Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let p = call(d, "tool.task.poll", json!({"id": id, "max": 16})).unwrap();
        if p["done"] == true {
            return p;
        }
        assert!(Instant::now() < deadline, "task did not finish: {p}");
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn the_daemon_authenticates_through_its_radius_service() {
    let stop = Arc::new(AtomicBool::new(false));
    let (port, srv) = radius_server(stop.clone());
    let d = start();
    call(
        &d,
        "radius.add",
        json!({"address": "127.0.0.1", "service": "ppp", "secret": SECRET,
               "authentication_port": port, "accounting_port": free_port()}),
    )
    .unwrap();
    let rows = call(&d, "radius.list", json!({})).unwrap();
    assert_eq!(rows[0]["secret"], "***");
    // Accept, with the reply's attributes decoded by name.
    let t = call(
        &d,
        "radius.test",
        json!({"user": "cliente1", "password": "senha1"}),
    )
    .unwrap();
    let done = until_done(&d, &t["id"]);
    let ev = &done["events"][0];
    assert_eq!(ev["outcome"], "accept", "{done}");
    assert_eq!(ev["server"], "*1");
    let attrs = ev["attributes"].as_array().unwrap();
    let rate = attrs
        .iter()
        .find(|a| a["name"] == "Mikrotik-Rate-Limit")
        .unwrap();
    assert_eq!(rate["value"], "50M/100M");
    // Reject.
    let t = call(
        &d,
        "radius.test",
        json!({"user": "cliente1", "password": "x"}),
    )
    .unwrap();
    assert_eq!(until_done(&d, &t["id"])["events"][0]["outcome"], "reject");
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let m = call(&d, "radius.monitor", json!({})).unwrap();
        if m[0]["accepts"] == 1 && m[0]["rejects"] == 1 {
            assert_eq!(m[0]["state"], "up");
            break;
        }
        assert!(Instant::now() < deadline, "{m}");
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(srv.lock().unwrap().stats.accepts, 1);
    // The log says it in Portuguese, topic radius. The service drains the
    // driver's log queue on its own tick, so the line can trail the reply
    // (flaked in CI, 2026-10-26).
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let log = call(&d, "log.print", json!({})).unwrap().to_string();
        if log.contains("recusado") {
            break;
        }
        assert!(Instant::now() < deadline, "{log}");
        thread::sleep(Duration::from_millis(50));
    }
    stop.store(true, Ordering::Relaxed);
}

#[test]
fn incoming_coa_without_a_session_owner_is_nak_503() {
    let d = start();
    let port = {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.local_addr().unwrap().port()
    };
    call(
        &d,
        "radius.add",
        json!({"address": "127.0.0.1", "service": "ppp", "secret": SECRET}),
    )
    .unwrap();
    call(
        &d,
        "radius.incoming.set",
        json!({"accept": true, "port": port}),
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while call(&d, "radius.incoming.get", json!({})).unwrap()["listening"].is_null() {
        assert!(Instant::now() < deadline, "incoming did not open");
        thread::sleep(Duration::from_millis(50));
    }
    let dac = UdpSocket::bind("127.0.0.1:0").unwrap();
    dac.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut l = AttrList::new();
    l.push_text(attr::ACCT_SESSION_ID, "PPP-404").unwrap();
    let req = dynauth::build_request(RequestKind::Disconnect, 7, &l, SECRET.as_bytes(), true);
    dac.send_to(&req, ("127.0.0.1", port)).unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = dac.recv_from(&mut buf).unwrap();
    let p = Packet::parse(&buf[..n]).unwrap();
    assert_eq!(p.code(), Code::DisconnectNak);
    assert_eq!(p.attr_u32(attr::ERROR_CAUSE), Some(503));
    // The counters follow within a refresh of the service's status.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let g = call(&d, "radius.incoming.get", json!({})).unwrap();
        if (g["requests"].as_u64(), g["naks"].as_u64()) == (Some(1), Some(1)) {
            assert_eq!(g["daemon"], true);
            break;
        }
        assert!(Instant::now() < deadline, "{g}");
        thread::sleep(Duration::from_millis(50));
    }
}

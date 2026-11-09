//! G4.6b: the NTP client of a `--backend linux` daemon in a throwaway
//! namespace. Its clock cannot change here (`CAP_SYS_TIME` is checked against
//! the initial user namespace, `crates/hal-linux/tests/netns_clock.rs`), so
//! this holds what can be seen from outside: it measures, says why it does
//! not correct, and reaches the server only through the configured VRF.
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_ntp
//! ```
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::net::UdpSocket;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use common::*;
use corerouter_proto_ntp::{MODE_SERVER, Packet, Timestamp};
use serde_json::{Value, json};
use socket2::{Domain, Protocol, Socket, Type};

const PORT: &str = "7983";
const SKEW_NANOS: i128 = 5_000_000_000;

fn run(command: &str, params: Value) -> Result<Value, String> {
    common::client(&format!("127.0.0.1:{PORT}"), common::token_of(None)).and_then(|mut c| {
        c.call(
            "engine.execute",
            json!({"command": command, "params": params}),
        )
    })
}

fn daemon(dir: &Path) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join("netns-ntp.log")).unwrap();
    let mut c = Command::new(DAEMON);
    c.args([
        "--backend",
        "linux",
        "--no-discovery",
        "--control",
        PORT,
        "--config-dir",
    ])
    .arg(dir)
    .arg("--token-file")
    .arg(common::token_file(None, dir))
    .env("RUST_LOG", "info")
    .stdout(Stdio::null())
    .stderr(log);
    let d = Kill(c.spawn().unwrap());
    wait_for("the daemon", || run("interface.list", json!({})).is_ok());
    d
}

/// An SNTP server `SKEW_NANOS` ahead on `addr`, inside device `device`.
fn server(addr: &str, device: Option<&str>) {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    if let Some(d) = device {
        sock.bind_device(Some(d.as_bytes())).unwrap();
    }
    let at: std::net::SocketAddr = format!("{addr}:123").parse().unwrap();
    sock.bind(&at.into()).unwrap();
    let sock: UdpSocket = sock.into();
    std::thread::spawn(move || {
        let mut buf = [0u8; 128];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(req) = Packet::decode(&buf[..n]) else {
                continue;
            };
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos() as i128;
            let now = Timestamp::from_unix_nanos(nanos + SKEW_NANOS);
            let reply = Packet {
                version: 4,
                mode: MODE_SERVER,
                stratum: 2,
                reference_id: *b"TEST",
                origin: req.transmit,
                receive: now,
                transmit: now,
                ..Packet::default()
            };
            let _ = sock.send_to(&reply.encode(), from);
        }
    });
}

fn status() -> Value {
    run("system.ntp.client.get", json!({})).unwrap()
}

#[test]
fn the_client_measures_explains_and_follows_the_vrf() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    let dir = tempdir();
    let _daemon = daemon(&dir);

    // The main table first: the server of `lo`.
    server("127.0.0.1", None);
    run(
        "system.ntp.client.set",
        json!({"enabled": true, "servers": ["127.0.0.1"]}),
    )
    .unwrap();
    wait_for("synchronized", || status()["status"] == "synchronized");
    let st = status();
    let off = st["system_offset_ms"].as_f64().unwrap();
    assert!((4_900.0..=5_100.0).contains(&off), "{st}");
    // No CAP_SYS_TIME in this namespace: it says so and keeps measuring.
    assert_eq!(st["clock"], "not-set", "{st}");
    assert!(
        st["clock_error"].as_str().unwrap().contains("CAP_SYS_TIME"),
        "{st}"
    );
    assert!(st["pending_step_ms"].is_null(), "{st}");

    // Nothing is waiting: there is nothing to confirm.
    let err = run("system.ntp.client.confirm-step", json!({})).unwrap_err();
    assert!(err.contains("no clock step"), "{err}");

    // The VRF: a server that exists only inside it.
    let vrf_ok = Command::new("ip")
        .args(["link", "add", "probe0", "type", "vrf", "table", "99"])
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success();
    if !vrf_ok {
        eprintln!("skipped the VRF part: module vrf is not loaded");
        return;
    }
    ip(None, &["link", "del", "probe0"]);
    run("ip.vrf.add", json!({"name": "red"})).unwrap();
    wait_for("the VRF device", || {
        Command::new("ip")
            .args(["link", "show", "red"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    });
    ip(None, &["link", "add", "d0", "type", "dummy"]);
    ip(None, &["link", "set", "d0", "master", "red", "up"]);
    ip(None, &["addr", "add", "10.77.0.1/24", "dev", "d0"]);
    server("10.77.0.1", Some("red"));

    // From the main table it is out of reach…
    run("system.ntp.client.set", json!({"servers": ["10.77.0.1"]})).unwrap();
    wait_for("the failure from main", || {
        status()["last_error"]
            .as_str()
            .is_some_and(|e| e.contains("10.77.0.1"))
    });
    assert_eq!(status()["status"], "waiting");
    // …and through the VRF it answers.
    run("system.ntp.client.set", json!({"vrf": "red"})).unwrap();
    wait_for("synchronized through the VRF", || {
        status()["synced_address"] == "10.77.0.1"
    });
    assert_eq!(status()["vrf"], "red");

    // A VRF in use cannot be a name that does not exist.
    let err = run("system.ntp.client.set", json!({"vrf": "nope"})).unwrap_err();
    assert!(err.contains("no VRF"), "{err}");
}

fn tempdir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("crntp-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

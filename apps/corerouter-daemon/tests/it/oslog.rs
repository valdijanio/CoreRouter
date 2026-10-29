//! G4.8b end to end: the real daemon's OS log over the control channel —
//! the virtual lab's made-up lines by default, this machine's kernel ring
//! and journal with `--os-log host`, the `os-log` service row in
//! `system.service.print`.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_control::Client;
use serde_json::{Value, json};

const DAEMON: &str = env!("CARGO_BIN_EXE_corerouter-daemon");

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

fn start(extra: &[&str]) -> Daemon {
    let port = free_port();
    let token_file =
        std::env::temp_dir().join(format!("cr-oslog-{}-{port}.token", std::process::id()));
    let child = Command::new(DAEMON)
        .args(["--control", &port.to_string()])
        .arg("--token-file")
        .arg(&token_file)
        .arg("--no-discovery")
        .args(extra)
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
    while !d.token_file.exists() || Client::connect(&d.control, Duration::from_secs(1)).is_err() {
        assert!(Instant::now() < deadline, "daemon did not start");
        thread::sleep(Duration::from_millis(50));
    }
    d
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
fn lab_daemon_shows_the_lab_os_log() {
    let d = start(&[]);
    let v = call(&d, "log.os.print", json!({}));
    assert_eq!(v["sources"][0]["name"], "lab", "{v}");
    let rows = v["entries"].as_array().unwrap();
    let ring = rows
        .iter()
        .find(|r| r["known"]["id"] == "nic-ring-full")
        .unwrap();
    assert_eq!(ring["count"], 37);
    // Incremental: nothing new right after.
    let last = v["last"].as_u64().unwrap();
    let again = call(&d, "log.os.print", json!({"since": last}));
    assert!(again["entries"].as_array().unwrap().len() <= 1);
    // The service may still be starting on a loaded machine.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let svc = call(&d, "system.service.print", json!({}));
        let row = svc
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == "os-log")
            .unwrap_or_else(|| panic!("no os-log row: {svc}"))
            .to_string();
        if row.contains("virtual lab") {
            break;
        }
        assert!(Instant::now() < deadline, "{row}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn host_daemon_reads_this_machine() {
    let d = start(&["--os-log", "host"]);
    let deadline = Instant::now() + Duration::from_secs(15);
    let v = loop {
        let v = call(&d, "log.os.print", json!({"limit": 50}));
        let names: Vec<&str> = v["sources"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| s["name"].as_str())
            .collect();
        if names == ["kmsg", "journal"] && v["total"].as_u64().unwrap_or(0) > 0 {
            break v;
        }
        if Instant::now() > deadline {
            // Neither source readable here: each must say why.
            for s in v["sources"].as_array().unwrap() {
                assert!(
                    s["ok"] == true || s["reason"].as_str().unwrap().starts_with("unavailable"),
                    "{s}"
                );
            }
            return;
        }
        thread::sleep(Duration::from_millis(200));
    };
    let rows = v["entries"].as_array().unwrap();
    assert!(!rows.is_empty() && rows.len() <= 50);
    assert!(
        rows.iter()
            .all(|r| r["level"].is_string() && r["source"].is_string())
    );
    assert!(rows.iter().any(|r| r["this_boot"] == true), "{v}");
    // Filters work on the real lines too.
    let k = call(&d, "log.os.print", json!({"source": "kernel", "limit": 20}));
    assert!(
        k["entries"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["source"] == "kernel")
    );
}

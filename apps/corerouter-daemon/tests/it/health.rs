//! G4.8a end to end: the real daemon (virtual lab) runs the `health`
//! service under its supervisor; its readings reach `system.resource.*`
//! over the control channel, the checks see the lab's bad cable and the
//! change goes to the router's log once.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

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
    token_file: std::path::PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.token_file);
    }
}

fn start() -> Daemon {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let token_file =
        std::env::temp_dir().join(format!("cr-health-{}-{port}.token", std::process::id()));
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

/// Ask until `ok` holds (the service reads every second while watched).
fn until(d: &Daemon, command: &str, ok: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let v = call(d, command, json!({}));
        if ok(&v) {
            return v;
        }
        assert!(Instant::now() < deadline, "{command} never got there: {v}");
        thread::sleep(Duration::from_millis(300));
    }
}

#[test]
fn the_health_service_feeds_resources_checks_and_the_log() {
    let d = start();
    let svc = until(&d, "system.service.print", |v| {
        v.as_array().is_some_and(|a| {
            a.iter()
                .any(|r| r["name"] == "health" && r["state"] == "running")
        })
    });
    assert!(svc.to_string().contains("health"));
    let p = until(&d, "system.resource.print", |v| v["cpu_load"].is_number());
    assert_eq!(p["cpu_count"], 16);
    let c = until(&d, "system.health.check", |v| {
        v["checks"].as_array().is_some_and(|a| {
            a.iter()
                .any(|c| c["key"] == "nic.errors" && c["severity"] == "warning")
        })
    });
    let services = c["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["key"] == "services")
        .unwrap()
        .clone();
    assert_eq!(
        services["severity"], "ok",
        "supervised and running: {services}"
    );
    let log = until(&d, "log.print", |v| {
        v.to_string().contains("Saúde: NIC errors")
    });
    assert_eq!(
        log.to_string().matches("Saúde: NIC errors").count(),
        1,
        "logged once"
    );
}

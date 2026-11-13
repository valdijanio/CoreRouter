//! G1.6zs end to end: `ip.service.www-ssl.set certificate=<name>` makes the
//! real daemon (virtual lab) serve HTTPS with that `/certificate`, and
//! `certificate=none` goes back to the router's own; the fingerprint is
//! read from the TLS handshake.
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
        std::env::temp_dir().join(format!("cr-webcert-{}-{port}.token", std::process::id()));
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

/// The fingerprint `addr` serves, once it is `want` (or any, with `None`).
fn served(addr: &str, want: Option<&str>) -> String {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let got = TcpStream::connect(addr)
            .ok()
            .and_then(|tcp| corerouter_control::tls::connect(tcp, None).ok())
            .map(|(_, fp)| fp);
        match (&got, want) {
            (Some(fp), Some(w)) if fp == w => return fp.clone(),
            (Some(fp), None) => return fp.clone(),
            _ => {}
        }
        assert!(
            Instant::now() < deadline,
            "{addr} never served {want:?} (last: {got:?})"
        );
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
fn www_ssl_serves_the_certificate_it_names() {
    let d = start();
    let port = free_port();
    let addr = format!("127.0.0.1:{port}");
    call(
        &d,
        "ip.service.www-ssl.set",
        json!({"enabled": true, "address": "127.0.0.1", "port": port}),
    );
    let own = served(&addr, None);

    call(
        &d,
        "certificate.add",
        json!({"name": "web", "subject_alt_name": "router.lan, 127.0.0.1"}),
    );
    let fp = call(&d, "certificate.print", json!({}))[0]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_ne!(fp, own);
    let r = call(&d, "ip.service.www-ssl.set", json!({"certificate": "web"}));
    assert_eq!(r["certificate"], "web");
    served(&addr, Some(&fp));
    let rows = call(&d, "certificate.print", json!({}));
    assert_eq!(rows[0]["used_by"], json!(["www-ssl"]));

    call(&d, "ip.service.www-ssl.set", json!({"certificate": "none"}));
    served(&addr, Some(&own));
}

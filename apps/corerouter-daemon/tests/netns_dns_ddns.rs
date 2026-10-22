//! G4.1c-3: RFC 2136 UPDATE with TSIG from BIND's `nsupdate` (an
//! independent client, as a DHCP server's dhcp-ddns would send it) on the
//! real port 53, inside a throwaway network namespace (no root, nothing
//! reaches the host):
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_dns_ddns
//! ```
//!
//! Checked: an add with a prerequisite answered at once (AA), the record a
//! dynamic `D` row, a delete, a wrong key refused with nothing changed,
//! and the A + PTR pair a DHCP lease gets. Skipped without `nsupdate`.
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::io::Write;
use std::net::{SocketAddr, UdpSocket};
use std::process::{Command, Stdio};
use std::time::Duration;

use common::*;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{Value, json};

const PORT: &str = "7998";
const SECRET: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";

fn run(command: &str, params: Value) -> Result<Value, String> {
    common::client(&format!("127.0.0.1:{PORT}"), common::token_of(None)).and_then(|mut c| {
        c.call(
            "engine.execute",
            json!({"command": command, "params": params}),
        )
    })
}

fn ask(name: &str, t: RecordType) -> Option<Message> {
    let mut m = Message::query();
    m.add_query(Query::query(Name::from_ascii(name).unwrap(), t));
    let s = UdpSocket::bind("10.53.0.2:0").unwrap();
    s.set_read_timeout(Some(Duration::from_millis(700)))
        .unwrap();
    s.send_to(&m.to_vec().unwrap(), SocketAddr::from(([10, 53, 0, 1], 53)))
        .unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = s.recv_from(&mut buf).ok()?;
    Message::from_vec(&buf[..n]).ok()
}

fn data(name: &str, t: RecordType) -> Vec<String> {
    ask(name, t)
        .map(|m| m.answers.iter().map(|r| r.data.to_string()).collect())
        .unwrap_or_default()
}

/// Runs `nsupdate -y` with `script`; whether it succeeded.
fn nsupdate(secret: &str, script: &str) -> (bool, String) {
    let mut c = Command::new("nsupdate")
        .args(["-y", &format!("hmac-sha256:ddns:{secret}")])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin
        .take()
        .unwrap()
        .write_all(format!("server 10.53.0.1\nzone lan.example\n{script}send\n").as_bytes())
        .unwrap();
    let out = c.wait_with_output().unwrap();
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn nsupdate_changes_the_zone() {
    if !in_netns() {
        return;
    }
    if Command::new("nsupdate").arg("-V").output().is_err() {
        eprintln!("nsupdate is not installed (bind9-dnsutils): skipped");
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    ip(None, &["link", "add", "lan0", "type", "dummy"]);
    ip(None, &["link", "set", "lan0", "up"]);
    for a in ["10.53.0.1/24", "10.53.0.2/24"] {
        ip(None, &["addr", "add", a, "dev", "lan0"]);
    }
    let dir = std::env::temp_dir().join(format!("g41c3-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log = std::fs::File::create(std::env::temp_dir().join("g41c3-netns.log")).unwrap();
    let mut c = Command::new(DAEMON);
    c.args(["--no-discovery", "--control", PORT, "--config-dir"])
        .arg(dir.join("cfg"))
        .arg("--token-file")
        .arg(common::token_file(None, &dir))
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(log);
    let _daemon = Kill(c.spawn().unwrap());
    wait_for("the daemon", || run("interface.list", json!({})).is_ok());

    run(
        "ip.dns.set",
        json!({"allow_remote_requests": true, "allowed_from": "10.53.0.0/24"}),
    )
    .unwrap();
    run(
        "ip.dns.tsig-key.add",
        json!({"name": "ddns", "secret": SECRET}),
    )
    .unwrap();
    run(
        "ip.dns.zone.add",
        json!({"name": "lan.example", "update_keys": "ddns"}),
    )
    .unwrap();
    run(
        "ip.dns.zone.add",
        json!({"name": "53.10.in-addr.arpa", "update_keys": "ddns"}),
    )
    .unwrap();
    wait_for("the zone", || {
        ask("lan.example.", RecordType::SOA).is_some_and(|m| m.metadata.authoritative)
    });
    let serial = |m: Option<Message>| m.map(|m| m.answers[0].data.to_string()).unwrap_or_default();
    let before = serial(ask("lan.example.", RecordType::SOA));

    // RFC 4703 §5.3.1 style: prerequisite "name not in use", then add.
    let (ok, out) = nsupdate(
        SECRET,
        "prereq nxdomain pc.lan.example\nupdate add pc.lan.example 300 A 10.53.0.50\n",
    );
    assert!(ok, "{out}");
    assert_eq!(data("pc.lan.example.", RecordType::A), ["10.53.0.50"]);
    assert_ne!(
        serial(ask("lan.example.", RecordType::SOA)),
        before,
        "§3.6: serial moved"
    );
    let rows = run("ip.dns.zone.record.print", json!({"name": "pc"})).unwrap();
    assert_eq!(rows[0]["flags"], "D", "{rows}");
    // The same prerequisite fails now (YXDOMAIN).
    let (ok, out) = nsupdate(
        SECRET,
        "prereq nxdomain pc.lan.example\nupdate add pc.lan.example 300 A 10.53.0.51\n",
    );
    assert!(!ok, "{out}");
    assert!(out.contains("YXDOMAIN"), "{out}");
    // A wrong key: refused, nothing changes.
    let (ok, out) = nsupdate(
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
        "update add evil.lan.example 300 A 10.53.0.66\n",
    );
    assert!(!ok, "{out}");
    assert!(data("evil.lan.example.", RecordType::A).is_empty());
    // Reverse zone too, then deletes.
    let (ok, out) = nsupdate(
        SECRET,
        "zone 53.10.in-addr.arpa\nupdate add 50.0.53.10.in-addr.arpa 300 PTR pc.lan.example.\n",
    );
    assert!(ok, "{out}");
    assert_eq!(
        data("50.0.53.10.in-addr.arpa.", RecordType::PTR),
        ["pc.lan.example."]
    );
    let (ok, out) = nsupdate(SECRET, "update delete pc.lan.example A\n");
    assert!(ok, "{out}");
    assert!(data("pc.lan.example.", RecordType::A).is_empty());
    let m = ask("pc.lan.example.", RecordType::A).unwrap();
    assert_eq!(
        m.metadata.response_code,
        hickory_proto::op::ResponseCode::NXDomain
    );
}

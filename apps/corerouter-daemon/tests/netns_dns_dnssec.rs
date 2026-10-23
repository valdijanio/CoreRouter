//! G4.1c-2: a signed zone validated by BIND's `delv` (an independent
//! validator) on the real port 53, inside a throwaway network namespace
//! (no root, nothing reaches the host):
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_dns_dnssec
//! ```
//!
//! The zone's KSK (from `ip.dns.zone.dnssec.print`) is the trust anchor:
//! an answer, an NXDOMAIN (NSEC3 closest encloser proof), a NODATA, an
//! empty non-terminal, a wildcard and a CNAME must all come out "fully
//! validated". Skipped when `delv` is not installed.
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::process::{Command, Stdio};

use common::*;
use serde_json::{Value, json};

const PORT: &str = "7997";

fn run(command: &str, params: Value) -> Result<Value, String> {
    common::client(&format!("127.0.0.1:{PORT}"), common::token_of(None)).and_then(|mut c| {
        c.call(
            "engine.execute",
            json!({"command": command, "params": params}),
        )
    })
}

fn delv(anchors: &std::path::Path, name: &str, t: &str) -> String {
    let out = Command::new("delv")
        .arg("@10.53.0.1")
        .arg("-a")
        .arg(anchors)
        .args(["+root=example.com", name, t])
        .output()
        .unwrap();
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn a_signed_zone_validates() {
    if !in_netns() {
        return;
    }
    if Command::new("delv").arg("-v").output().is_err() {
        eprintln!("delv is not installed (bind9-dnsutils): skipped");
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    ip(None, &["link", "add", "lan0", "type", "dummy"]);
    ip(None, &["link", "set", "lan0", "up"]);
    ip(None, &["addr", "add", "10.53.0.1/24", "dev", "lan0"]);
    let dir = std::env::temp_dir().join(format!("g41c2-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log = std::fs::File::create(std::env::temp_dir().join("g41c2-netns.log")).unwrap();
    let mut c = Command::new(DAEMON);
    c.args([
        "--no-discovery",
        "--dns-lab-any",
        "--control",
        PORT,
        "--config-dir",
    ])
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
        json!({"allow_remote_requests": true, "allowed_from": "0.0.0.0/0"}),
    )
    .unwrap();
    run(
        "ip.dns.zone.add",
        json!({"name": "example.com", "dnssec": true}),
    )
    .unwrap();
    for (name, t, extra) in [
        ("@", "NS", json!({"target": "ns1.example.com"})),
        ("ns1", "A", json!({"address": "10.53.0.1"})),
        ("www", "A", json!({"address": "192.0.2.80"})),
        ("*.dev", "A", json!({"address": "192.0.2.99"})),
        ("a.b", "TXT", json!({"text": "deep"})),
        ("alias", "CNAME", json!({"target": "www.example.com"})),
        ("sub", "NS", json!({"target": "ns.sub.example.com"})),
        ("ns.sub", "A", json!({"address": "192.0.2.153"})),
    ] {
        let mut p = json!({"zone": "example.com", "name": name, "type": t});
        p.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        run("ip.dns.zone.record.add", p).unwrap();
    }
    let mut ksk = String::new();
    wait_for("the KSK and the signed zone", || {
        let keys = run("ip.dns.zone.dnssec.print", json!({})).unwrap_or_default();
        let zone = run("ip.dns.zone.print", json!({})).unwrap_or_default();
        let found = keys.as_array().and_then(|a| {
            a.iter()
                .find(|k| k["role"] == "ksk")
                .and_then(|k| k["dnskey"].as_str().map(str::to_owned))
        });
        let signed = zone[0]["signed_serial"].as_u64() == zone[0]["serial"].as_u64();
        if let Some(k) = found {
            ksk = k;
        }
        !ksk.is_empty() && signed
    });
    // `257 3 13 <base64>` → static-key 257 3 13 "<base64>".
    let mut parts = ksk.splitn(4, ' ');
    let (f, p, a, key) = (
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
        parts.next().unwrap(),
    );
    let anchors = dir.join("anchors.conf");
    std::fs::write(
        &anchors,
        format!("trust-anchors {{ example.com. static-key {f} {p} {a} \"{key}\"; }};\n"),
    )
    .unwrap();
    for (name, t, want) in [
        ("www.example.com", "A", "; fully validated"),
        ("example.com", "SOA", "; fully validated"),
        ("example.com", "DNSKEY", "; fully validated"),
        (
            "nope.example.com",
            "A",
            "; negative response, fully validated",
        ),
        (
            "www.example.com",
            "TXT",
            "; negative response, fully validated",
        ),
        ("b.example.com", "A", "; negative response, fully validated"),
        ("x.y.dev.example.com", "A", "; fully validated"),
        ("alias.example.com", "A", "; fully validated"),
    ] {
        let out = delv(&anchors, name, t);
        assert!(out.contains(want), "{name} {t}:\n{out}");
        eprintln!("{name} {t}: {}", out.lines().next().unwrap_or_default());
    }
    // A change is re-signed and still validates.
    run(
        "ip.dns.zone.record.add",
        json!({"zone": "example.com", "name": "new", "address": "192.0.2.50"}),
    )
    .unwrap();
    wait_for("the re-signed change", || {
        delv(&anchors, "new.example.com", "A").contains("; fully validated")
    });
}

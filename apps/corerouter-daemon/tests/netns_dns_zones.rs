//! G4.1c: authoritative zones on the real port 53, inside a throwaway
//! network namespace (no root, nothing reaches the host):
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_dns_zones
//! ```
//!
//! A dummy `lan0` holds the router (10.53.0.1), a secondary allowed to
//! transfer (10.53.0.2) and a stranger (10.53.0.4). Checked: answers with
//! AA, NXDOMAIN with the SOA, AXFR and IXFR by `dig` (when installed) and
//! by our own transfer client, REFUSED outside `allow_transfer`, and a
//! zone file loaded by command served at once with a new serial.
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::time::Duration;

use common::*;
use corerouter_proto_dns::zone::xfr::{self, Transfer};
use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use serde_json::{Value, json};

const PORT: &str = "7996";
const ROUTER: [u8; 4] = [10, 53, 0, 1];
const SECONDARY: [u8; 4] = [10, 53, 0, 2];
const STRANGER: [u8; 4] = [10, 53, 0, 4];

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
    let s = UdpSocket::bind(SocketAddr::from((SECONDARY, 0))).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(700)))
        .unwrap();
    s.send_to(&m.to_vec().unwrap(), SocketAddr::from((ROUTER, 53)))
        .unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = s.recv_from(&mut buf).ok()?;
    Message::from_vec(&buf[..n]).ok()
}

/// A transfer with our own client, from `from`.
fn transfer(from: [u8; 4], q: &[u8], id: u16, ixfr: bool) -> Result<Transfer, String> {
    let sock = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
    sock.bind(&SocketAddr::from((from, 0)).into()).unwrap();
    sock.connect(&SocketAddr::from((ROUTER, 53)).into())
        .unwrap();
    let mut s: TcpStream = sock.into();
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut framed = u16::try_from(q.len()).unwrap().to_be_bytes().to_vec();
    framed.extend_from_slice(q);
    s.write_all(&framed).unwrap();
    let mut t = Transfer::new(id, "example.com", ixfr);
    loop {
        let mut head = [0u8; 2];
        s.read_exact(&mut head).map_err(|e| e.to_string())?;
        let mut msg = vec![0u8; usize::from(u16::from_be_bytes(head))];
        s.read_exact(&mut msg).map_err(|e| e.to_string())?;
        if t.push(&msg)? {
            return Ok(t);
        }
    }
}

fn dig(args: &[&str]) -> Option<String> {
    let out = Command::new("dig").args(args).output().ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn zones_are_served_and_transferred() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    ip(None, &["link", "add", "lan0", "type", "dummy"]);
    ip(None, &["link", "set", "lan0", "up"]);
    for a in ["10.53.0.1/24", "10.53.0.2/24", "10.53.0.4/24"] {
        ip(None, &["addr", "add", a, "dev", "lan0"]);
    }
    let dir = std::env::temp_dir().join(format!("g41c-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let log = std::fs::File::create(std::env::temp_dir().join("g41c-netns.log")).unwrap();
    let mut c = Command::new(DAEMON);
    c.args(["--no-discovery", "--control", PORT, "--config-dir"])
        .arg(&dir)
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
        "ip.dns.zone.add",
        json!({"name": "example.com", "allow_transfer": "10.53.0.2/32"}),
    )
    .unwrap();
    for (name, t, extra) in [
        ("@", "NS", json!({"target": "ns1.example.com"})),
        ("ns1", "A", json!({"address": "10.53.0.1"})),
        ("www", "A", json!({"address": "192.0.2.80"})),
        (
            "@",
            "MX",
            json!({"target": "mail.example.com", "priority": 10}),
        ),
        ("mail", "A", json!({"address": "192.0.2.25"})),
    ] {
        let mut p = json!({"zone": "example.com", "name": name, "type": t});
        p.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        run("ip.dns.zone.record.add", p).unwrap();
    }
    wait_for("the zone", || {
        ask("www.example.com.", RecordType::A).is_some_and(|m| m.metadata.authoritative)
    });
    let m = ask("www.example.com.", RecordType::A).unwrap();
    assert_eq!(m.answers[0].data.to_string(), "192.0.2.80");
    let m = ask("nope.example.com.", RecordType::A).unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(m.authorities[0].record_type(), RecordType::SOA);

    // AXFR by our client: SOA, 5 records, SOA.
    let (id, q) = xfr::xfr_query("example.com", None).unwrap();
    let t = transfer(SECONDARY, &q, id, false).unwrap();
    let zone = t.finish(None).unwrap().unwrap();
    assert_eq!(zone.len(), 5);
    // A stranger: REFUSED (a single message that ends the transfer).
    assert!(transfer(STRANGER, &q, id, false).is_err());

    // A change, then IXFR from the old serial.
    run(
        "ip.dns.zone.record.add",
        json!({"zone": "example.com", "name": "new", "address": "192.0.2.50"}),
    )
    .unwrap();
    wait_for("the change", || {
        ask("new.example.com.", RecordType::A).is_some_and(|m| !m.answers.is_empty())
    });
    let (id, q) = xfr::xfr_query("example.com", Some(&zone)).unwrap();
    let t = transfer(SECONDARY, &q, id, true).unwrap();
    let newer = t.finish(Some(&zone)).unwrap().unwrap();
    assert_eq!(newer.len(), 6);
    assert!(newer.serial != zone.serial);

    // dig, when the host has it (dnsutils).
    if let Some(out) = dig(&[
        "+tcp",
        "-b",
        "10.53.0.2",
        "@10.53.0.1",
        "example.com",
        "AXFR",
    ]) {
        assert!(out.contains("www.example.com."), "{out}");
        assert!(out.contains("XFR size: 8 records"), "{out}");
        let ixfr = format!("IXFR={}", zone.serial);
        let out = dig(&["-b", "10.53.0.2", "@10.53.0.1", "example.com", &ixfr]).unwrap();
        assert!(out.contains("new.example.com."), "{out}");
        let out = dig(&[
            "+tcp",
            "-b",
            "10.53.0.4",
            "@10.53.0.1",
            "example.com",
            "AXFR",
        ])
        .unwrap();
        assert!(
            out.contains("Transfer failed") || out.contains("REFUSED"),
            "{out}"
        );
        let out = dig(&["+norec", "-b", "10.53.0.2", "@10.53.0.1", "www.example.com"]).unwrap();
        assert!(out.contains(" aa"), "{out}");
    } else {
        eprintln!("dig is not installed: the dig checks were skipped");
    }

    // A zone file by command: served at once, serial moved.
    let before = run("ip.dns.zone.print", json!({})).unwrap()[0]["serial"].clone();
    let text = "$TTL 300\n@ SOA ns1 hostmaster 1 3600 600 86400 300\n@ NS ns1\nns1 A 10.53.0.1\nwww A 192.0.2.99\n";
    run(
        "ip.dns.zone.file.load",
        json!({"zone": "example.com", "text": text}),
    )
    .unwrap();
    wait_for("the loaded file", || {
        ask("www.example.com.", RecordType::A).is_some_and(|m| {
            m.answers
                .first()
                .is_some_and(|r| r.data.to_string() == "192.0.2.99")
        })
    });
    let after = run("ip.dns.zone.print", json!({})).unwrap()[0]["serial"].clone();
    assert_ne!(before, after);
    let m = ask("mail.example.com.", RecordType::A).unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain, "replaced");
}

//! G4.1a: the daemon resolves names with its own resolver (`/ip dns`), not
//! the host's — inside a throwaway network namespace, no root, nothing
//! reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_dns
//! ```
//!
//! The namespace has only `lo` and no `/etc/resolv.conf` server that
//! answers (systemd-resolved's `127.0.0.53` lives in the host's
//! namespace), exactly like the router's image. A test DNS server written
//! here, on the real port 53 of `127.0.0.2`, answers `*.test` with
//! `127.0.0.1` and NXDOMAIN (with SOA) for `nope.test`. Ping (the host's
//! ICMP, `--lab-ping host`) must reach `router.test` through it, and the
//! answer must be in `ip.dns.cache.print`.
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::*;
use hickory_proto::op::{Message, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use serde_json::{Value, json};

const PORT: &str = "7996";

fn run(command: &str, params: Value) -> Result<Value, String> {
    common::client(&format!("127.0.0.1:{PORT}"), common::token_of(None)).and_then(|mut c| {
        c.call(
            "engine.execute",
            json!({"command": command, "params": params}),
        )
    })
}

/// The test server; returns how many queries it got.
fn serve() -> Arc<AtomicUsize> {
    let sock = UdpSocket::bind("127.0.0.2:53").unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    std::thread::spawn(move || {
        let mut buf = [0u8; 1500];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            c.fetch_add(1, Ordering::Relaxed);
            let Ok(q) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            let Some(qq) = q.queries.first().cloned() else {
                continue;
            };
            let mut m = Message::response(q.metadata.id, OpCode::Query);
            m.metadata.recursion_available = true;
            m.add_query(qq.clone());
            let soa = Record::from_rdata(
                Name::from_ascii("test.").unwrap(),
                60,
                RData::SOA(SOA::new(
                    Name::from_ascii("ns.test.").unwrap(),
                    Name::from_ascii("admin.test.").unwrap(),
                    1,
                    3600,
                    600,
                    86_400,
                    60,
                )),
            );
            if qq.name().to_ascii().starts_with("nope.") {
                m.metadata.response_code = ResponseCode::NXDomain;
                m.add_authority(soa);
            } else if qq.query_type() == RecordType::A {
                m.add_answer(Record::from_rdata(
                    qq.name().clone(),
                    300,
                    RData::A(A([127, 0, 0, 1].into())),
                ));
            } else {
                m.add_authority(soa);
            }
            let _ = sock.send_to(&m.to_vec().unwrap(), from);
        }
    });
    count
}

fn until_done(id: &Value) -> Value {
    let mut last = Value::Null;
    wait_for("the ping task", || {
        last = run("tool.task.poll", json!({"id": id, "max": 64})).unwrap();
        last["done"] == true
    });
    last
}

#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn ping_resolves_through_the_router_resolver() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    let queries = serve();

    let dir = std::env::temp_dir().join(format!("g41a-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let log = std::fs::File::create(std::env::temp_dir().join("g41a-netns.log")).unwrap();
    let mut c = Command::new(DAEMON);
    c.args([
        "--no-discovery",
        "--lab-ping",
        "host",
        "--control",
        PORT,
        "--config-dir",
    ])
    .arg(&dir)
    .arg("--token-file")
    .arg(common::token_file(None, &dir))
    .env("RUST_LOG", "info")
    .stdout(Stdio::null())
    .stderr(log);
    let _daemon = Kill(c.spawn().unwrap());
    wait_for("the daemon", || run("interface.list", json!({})).is_ok());

    // No server yet: the host prober has no resolver of its own.
    let t = run(
        "tool.ping.start",
        json!({"address": "router.test", "count": 1}),
    )
    .unwrap();
    let p = until_done(&t["task_id"]);
    assert!(p.to_string().contains("no DNS server configured"), "{p}");
    assert_eq!(queries.load(Ordering::Relaxed), 0);

    run("ip.dns.set", json!({"servers": ["127.0.0.2"]})).unwrap();
    // The resolver picks the config up within a second.
    std::thread::sleep(Duration::from_millis(1500));
    let t = run(
        "tool.ping.start",
        json!({"address": "router.test", "count": 1, "interval_ms": 100}),
    )
    .unwrap();
    let p = until_done(&t["task_id"]);
    assert_eq!(p["summary"]["targets"][0]["received"], 1, "{p}");
    assert_eq!(p["events"][0]["address"], "127.0.0.1", "{p}");
    assert!(queries.load(Ordering::Relaxed) >= 1);

    let cache = run("ip.dns.cache.print", json!({})).unwrap();
    let row = cache
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "router.test" && r["type"] == "A")
        .unwrap_or_else(|| panic!("{cache}"));
    assert_eq!(row["addresses"], json!(["127.0.0.1"]));
    assert_eq!(row["server"], "127.0.0.2");

    // NXDOMAIN with SOA: an error for the tool, and cached (RFC 2308).
    let before = queries.load(Ordering::Relaxed);
    for _ in 0..2 {
        let t = run(
            "tool.ping.start",
            json!({"address": "nope.test", "count": 1}),
        )
        .unwrap();
        let p = until_done(&t["task_id"]);
        assert!(p.to_string().contains("could not be resolved"), "{p}");
    }
    assert_eq!(
        queries.load(Ordering::Relaxed),
        before + 1,
        "second from the cache"
    );

    let flushed = run("ip.dns.cache.flush", json!({})).unwrap();
    assert!(flushed["flushed"].as_u64().unwrap() >= 2, "{flushed}");
    assert_eq!(run("ip.dns.cache.print", json!({})).unwrap(), json!([]));
}

//! G4.6c: the NTP server of a `--backend linux` daemon in a throwaway
//! namespace, from outside, over real sockets on port 123.
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_ntp_server
//! ```
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use common::*;
use corerouter_proto_ntp::server::MODE_BROADCAST;
use corerouter_proto_ntp::{MODE_SERVER, Packet, Timestamp, check_reply};
use serde_json::{Value, json};
use socket2::{Domain, Protocol, Socket, Type};

const PORT: &str = "7985";

fn run(command: &str, params: Value) -> Result<Value, String> {
    common::client(&format!("127.0.0.1:{PORT}"), common::token_of(None)).and_then(|mut c| {
        c.call(
            "engine.execute",
            json!({"command": command, "params": params}),
        )
    })
}

fn daemon(dir: &Path) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join("netns-ntp-server.log")).unwrap();
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

fn nanos() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i128
}

/// A source of time on `127.0.0.2:123`, sharing the port with the server's
/// wildcard sockets (`SO_REUSEPORT`; the more specific address wins).
fn upstream() {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    sock.set_reuse_port(true).unwrap();
    let at: SocketAddr = "127.0.0.2:123".parse().unwrap();
    sock.bind(&at.into()).unwrap();
    let sock: UdpSocket = sock.into();
    std::thread::spawn(move || {
        let mut buf = [0u8; 128];
        while let Ok((n, from)) = sock.recv_from(&mut buf) {
            let Ok(req) = Packet::decode(&buf[..n]) else {
                continue;
            };
            let now = Timestamp::from_unix_nanos(nanos());
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

/// A connected socket from `src`: the kernel delivers only a reply that comes
/// from the very address asked, so this also holds `IP_PKTINFO`.
fn client(src: &str, dst: &str) -> UdpSocket {
    let s = UdpSocket::bind((src, 0)).unwrap();
    s.connect((dst, 123)).unwrap();
    s.set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    s
}

fn ask(s: &UdpSocket) -> Option<Packet> {
    let sent = Timestamp::from_unix_nanos(nanos());
    s.send(&Packet::client_request(sent).encode()).unwrap();
    let mut buf = [0u8; 128];
    let n = s.recv(&mut buf).ok()?;
    let p = Packet::decode(&buf[..n]).unwrap();
    assert_eq!(p.origin, sent);
    Some(p)
}

fn stats() -> Value {
    run("system.ntp.server.get", json!({})).unwrap()
}

#[test]
fn the_server_from_outside() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    ip(None, &["link", "add", "d0", "type", "dummy"]);
    ip(None, &["link", "set", "d0", "up"]);
    ip(None, &["addr", "add", "10.7.0.1/24", "dev", "d0"]);
    ip(None, &["addr", "add", "10.7.0.2/24", "dev", "d0"]);
    ip(None, &["addr", "add", "198.51.100.1/32", "dev", "d0"]);
    upstream();
    let dir = std::env::temp_dir().join(format!("crntps-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let _daemon = daemon(&dir);
    let lan = client("10.7.0.2", "10.7.0.1");

    // Off by default: nothing listens.
    assert!(ask(&lan).is_none());
    assert_eq!(stats()["listening"], false);

    // On, not synchronized: silence.
    run("system.ntp.server.set", json!({"enabled": true})).unwrap();
    wait_for("listening", || stats()["listening"] == true);
    assert!(ask(&lan).is_none(), "before the client synchronizes");
    assert_eq!(stats()["serving"], "no");

    // The client synchronizes: stratum 2 + 1, from the address asked.
    run(
        "system.ntp.client.set",
        json!({"enabled": true, "servers": ["127.0.0.2"]}),
    )
    .unwrap();
    wait_for("serving", || ask(&lan).is_some());
    let sent = Timestamp::from_unix_nanos(nanos());
    lan.send(&Packet::client_request(sent).encode()).unwrap();
    let mut buf = [0u8; 128];
    let n = lan.recv(&mut buf).unwrap();
    assert_eq!(n, 48, "only the header");
    let r = Packet::decode(&buf[..n]).unwrap();
    assert_eq!(check_reply(sent, &r), Ok(()));
    assert_eq!(r.stratum, 3);
    assert_eq!(r.reference_id, [127, 0, 0, 2]);
    assert!((r.transmit.to_unix_nanos() - nanos()).abs() < 2_000_000_000);
    assert!(r.receive.to_unix_nanos() <= r.transmit.to_unix_nanos());
    assert_eq!(stats()["serving"], "upstream");

    // The other local address answers from itself, not from the first.
    assert_eq!(ask(&client("10.7.0.1", "10.7.0.2")).unwrap().stratum, 3);
    // IPv6 too.
    let v6 = UdpSocket::bind("[::1]:0").unwrap();
    v6.connect(SocketAddr::new(
        IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        123,
    ))
    .unwrap();
    v6.set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    assert_eq!(ask(&v6).unwrap().stratum, 3);

    // A public source: silence by default.
    let wan = client("198.51.100.1", "10.7.0.1");
    assert!(ask(&wan).is_none(), "a public source");
    wait_for("denied", || stats()["denied"].as_u64().unwrap() > 0);

    // Modes 6 and 7, and a request with extension fields.
    let ctl = client("10.7.0.2", "10.7.0.1");
    for mode in [6u8, 7] {
        let mut p = Packet::client_request(Timestamp::from_unix_nanos(nanos()));
        p.mode = mode;
        ctl.send(&p.encode()).unwrap();
        assert!(ctl.recv(&mut buf).is_err(), "mode {mode} got an answer");
    }
    let mut long = Packet::client_request(Timestamp::from_unix_nanos(nanos()))
        .encode()
        .to_vec();
    long.extend_from_slice(&[0u8; 28]);
    ctl.send(&long).unwrap();
    assert_eq!(
        ctl.recv(&mut buf).unwrap(),
        48,
        "extension fields are not echoed"
    );

    // Hostile bytes: an answer is the header and nothing else, and the server
    // survives. (Replies arrive late, so they cannot be matched to a request.)
    let junk = client("10.7.0.2", "10.7.0.1");
    junk.set_read_timeout(Some(Duration::from_millis(2)))
        .unwrap();
    let mut x = 0x1234_5678u32;
    let mut wrong_size = 0;
    for i in 0..2000usize {
        let len = i % 600;
        let bytes: Vec<u8> = (0..len)
            .map(|_| {
                x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                (x >> 24) as u8
            })
            .collect();
        if junk.send(&bytes).is_ok()
            && i % 50 == 0
            && let Ok(n) = junk.recv(&mut buf)
        {
            wrong_size += usize::from(n != 48);
        }
    }
    assert_eq!(wrong_size, 0);
    assert!(run("interface.list", json!({})).is_ok());

    // A flood from one source: its burst, one RATE kiss, then silence.
    run("system.ntp.server.set", json!({"allowed": ["10.7.0.3/32"]})).unwrap();
    ip(None, &["addr", "add", "10.7.0.3/24", "dev", "d0"]);
    let flood = client("10.7.0.3", "10.7.0.1");
    wait_for("the new list", || {
        ask(&client("10.7.0.2", "10.7.0.1")).is_none()
    });
    flood
        .set_read_timeout(Some(Duration::from_millis(20)))
        .unwrap();
    let (mut replies, mut kiss, mut silence) = (0, 0, 0);
    for _ in 0..40 {
        match ask(&flood) {
            Some(p) if p.stratum == 0 => {
                assert_eq!(p.kiss_code().as_deref(), Some("RATE"));
                assert_eq!(
                    check_reply(p.origin, &p),
                    Err(corerouter_proto_ntp::ReplyError::Kiss("RATE".into()))
                );
                kiss += 1;
            }
            Some(_) => replies += 1,
            None => silence += 1,
        }
    }
    // Readers do not share a table, but one connected socket hashes to one.
    // A new credit every 2 s may arrive while this runs.
    assert!((16..=18).contains(&replies), "{replies} replies");
    assert_eq!(kiss, 1, "silence {silence}");
    assert!(silence > 0);
    wait_for("the counters", || {
        let s = stats();
        s["kisses"].as_u64().unwrap() >= 1 && s["limited"].as_u64().unwrap() > 0
    });

    // A firewall address list: nobody until an entry names the client. A
    // dynamic entry counts too.
    run("system.ntp.server.set", json!({"allowed": ["ntp-lan"]})).unwrap();
    let member = client("10.7.0.2", "10.7.0.1");
    wait_for("the list applied", || ask(&member).is_none());
    wait_for("the empty list reported", || {
        stats()["empty_lists"] == json!(["ntp-lan"])
    });
    run(
        "ip.firewall.address-list.add",
        json!({"list": "ntp-lan", "address": "10.7.0.2", "timeout": "1h"}),
    )
    .unwrap();
    wait_for("the entry counts", || ask(&member).is_some());
    wait_for("no complaint", || stats()["empty_lists"] == json!([]));
    assert!(
        ask(&client("10.7.0.3", "10.7.0.1")).is_none(),
        "not on the list"
    );

    // Broadcast: mode 5 to the subnet's address.
    run(
        "system.ntp.server.set",
        json!({"allowed": ["10.0.0.0/8"], "broadcast": true, "broadcast_addresses": ["10.7.0.255"]}),
    )
    .unwrap();
    let listen = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    listen.set_reuse_port(true).unwrap();
    let at: SocketAddr = "10.7.0.255:123".parse().unwrap();
    listen.bind(&at.into()).unwrap();
    let listen: UdpSocket = listen.into();
    listen
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let start = Instant::now();
    let n = listen.recv(&mut buf).expect("a broadcast within 10 s");
    let b = Packet::decode(&buf[..n]).unwrap();
    assert_eq!(b.mode, MODE_BROADCAST, "after {:?}", start.elapsed());
    assert_eq!(b.stratum, 3);
    assert!(b.origin.is_zero());

    // A VRF: the server hears only inside it.
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
    run(
        "system.ntp.server.set",
        json!({"broadcast": false, "vrf": "red"}),
    )
    .unwrap();
    ip(None, &["link", "add", "d1", "type", "dummy"]);
    ip(None, &["link", "set", "d1", "master", "red", "up"]);
    ip(None, &["addr", "add", "10.8.0.1/24", "dev", "d1"]);
    ip(None, &["addr", "add", "10.8.0.2/24", "dev", "d1"]);
    wait_for("out of the main table", || {
        ask(&client("10.7.0.2", "10.7.0.1")).is_none()
    });
    let inside = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
    inside.bind_device(Some(b"red")).unwrap();
    let src: SocketAddr = "10.8.0.2:0".parse().unwrap();
    inside.bind(&src.into()).unwrap();
    let dst: SocketAddr = "10.8.0.1:123".parse().unwrap();
    inside.connect(&dst.into()).unwrap();
    let inside: UdpSocket = inside.into();
    inside
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    wait_for("an answer inside the VRF", || {
        ask(&inside).is_some_and(|p| p.stratum == 3)
    });
}

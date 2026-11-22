//! G4.3f: a `--backend linux` daemon's IPoE subscribers: DHCP clients this
//! test simulates (raw frames, one MAC each) across a veth, inside a
//! throwaway network namespace, no root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_ipoe -- --test-threads 1
//! ```
//!
//! ```text
//!   daemon (DHCP server + ipoe)           this test
//!   acc0 10.64.0.1/16 ─────── veth ────── cpe0: N DHCP clients (raw frames)
//!   RADIUS: proto_radius::testserver on 127.0.0.1
//! ```
//!
//! One subscriber from the local list; then 10 000 authorized by RADIUS
//! (`use_radius=yes`, the MAC as User-Name, the Accept's rate and
//! Framed-IP), with an Accounting-Start each; RADIUS rejects stay without
//! an address and "Why?" says so; `ppp.active.remove` ends one. The setup
//! rate and the daemon's memory per session are printed (`docs/perf.md`).
//! Without root there is no XDP here: the sessions exist without the
//! policer (the XDP path is `hal-linux`'s `xdp_root` test).
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};
use std::os::fd::AsRawFd;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use corerouter_proto_dhcp::v4::{self, Outgoing};
use corerouter_proto_radius::packet::{AttrList, PushAttr, attr};
use corerouter_proto_radius::testserver::TestServer;
use dhcproto::v4::MessageType;
use serde_json::{Value, json};
use socket2::{Domain, Protocol, Socket, Type};

fn daemon(dir: &std::path::Path) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join("g43f-ipoe.log")).unwrap();
    let mut c = in_ns(None, DAEMON);
    c.args([
        "--backend",
        "linux",
        "--no-discovery",
        "--manage",
        "acc0",
        "--control",
        "7979",
        "--config-dir",
    ])
    .arg(dir)
    .arg("--token-file")
    .arg(token_file(None, dir))
    .env("RUST_LOG", "info")
    .stdout(Stdio::null())
    .stderr(log);
    let k = Kill(c.spawn().unwrap());
    wait_for("the daemon", || {
        call(None, "interface.list", json!({})).is_ok()
    });
    k
}

fn ok(command: &str, params: Value) -> Value {
    call(None, command, params).unwrap_or_else(|e| panic!("{command}: {e}"))
}

fn active() -> Vec<Value> {
    ok("ppp.active.list", json!({"limit": 100_000}))["rows"]
        .as_array()
        .unwrap()
        .clone()
}

fn rss_kib(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap_or(0)
}

/// A raw IPv4 socket on cpe0: the clients' frames out, the server's in.
struct Wire {
    sock: Socket,
}

impl Wire {
    fn open() -> Self {
        let link = nix::ifaddrs::getifaddrs()
            .unwrap()
            .filter(|a| a.interface_name == "cpe0")
            .find_map(|a| a.address.and_then(|x| x.as_link_addr().copied()))
            .unwrap();
        let sock = Socket::new(
            Domain::PACKET,
            Type::RAW,
            Some(Protocol::from(i32::from(0x0800u16.to_be()))),
        )
        .unwrap();
        sock.set_nonblocking(true).unwrap();
        let _ = sock.set_recv_buffer_size(16 << 20);
        let _ = sock.set_send_buffer_size(16 << 20);
        nix::sys::socket::bind(sock.as_raw_fd(), &link).unwrap();
        Wire { sock }
    }

    fn send(&self, f: &[u8]) {
        // A full buffer: the client retransmits.
        let _ = nix::sys::socket::send(
            self.sock.as_raw_fd(),
            f,
            nix::sys::socket::MsgFlags::empty(),
        );
    }

    fn recv(&self, mut f: impl FnMut(&[u8])) {
        let mut buf = [0u8; 2048];
        for _ in 0..4096 {
            match nix::sys::socket::recv(
                self.sock.as_raw_fd(),
                &mut buf,
                nix::sys::socket::MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(n) => f(&buf[..n]),
                Err(_) => break,
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Phase {
    Idle,
    Discovering,
    Requesting(Ipv4Addr, Ipv4Addr),
    Bound(Ipv4Addr),
}

/// The simulated DHCP clients (RFC 2131 §4.4: DISCOVER, OFFER, REQUEST,
/// ACK, retransmitting every 2 s).
struct Clients {
    wire: Wire,
    macs: Vec<[u8; 6]>,
    by_mac: HashMap<[u8; 6], usize>,
    phase: Vec<Phase>,
    sent: Vec<Instant>,
}

fn mac(k: usize) -> [u8; 6] {
    [0x02, 0x30, (k >> 16) as u8, (k >> 8) as u8, k as u8, 0x01]
}

fn mac_text(m: [u8; 6]) -> String {
    m.iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

impl Clients {
    fn new(base: usize, n: usize) -> Self {
        let macs: Vec<[u8; 6]> = (base..base + n).map(mac).collect();
        let by_mac = macs.iter().enumerate().map(|(i, m)| (*m, i)).collect();
        Clients {
            wire: Wire::open(),
            macs,
            by_mac,
            phase: vec![Phase::Idle; n],
            sent: vec![Instant::now(); n],
        }
    }

    fn send(&mut self, i: usize) {
        let m = self.macs[i];
        let (kind, requested, server) = match self.phase[i] {
            Phase::Requesting(ip, sid) => (MessageType::Request, Some(ip), Some(sid)),
            _ => (MessageType::Discover, None, None),
        };
        let payload = Outgoing {
            kind,
            xid: u32::from_be_bytes([m[2], m[3], m[4], m[5]]),
            secs: 0,
            mac: m,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            broadcast: true,
            requested,
            server_id: server,
            client_id: &[],
            host_name: None,
            vendor_class: None,
            extra: &[],
        }
        .encode()
        .unwrap();
        let f = corerouter_hal_linux::dhcp::udp_frame(
            m,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            &payload,
        )
        .unwrap();
        self.wire.send(&f);
        self.sent[i] = Instant::now();
    }

    fn bound(&self) -> usize {
        self.phase
            .iter()
            .filter(|p| matches!(p, Phase::Bound(_)))
            .count()
    }

    /// Run until `want` are bound or `secs` pass; new DISCOVERs go out at
    /// most `per_ms` a millisecond (a reboot storm, paced).
    fn run(&mut self, want: usize, secs: u64, per_ms: usize) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        let mut next = 0;
        while Instant::now() < deadline {
            let mut started = 0;
            while next < self.macs.len() && started < per_ms {
                if self.phase[next] == Phase::Idle {
                    self.phase[next] = Phase::Discovering;
                    self.send(next);
                }
                next += 1;
                started += 1;
            }
            let mut got = Vec::new();
            self.wire.recv(|f| {
                if let Some(d) = corerouter_hal_linux::dhcp::parse_frame(f)
                    && let Ok(m) = v4::decode(&d.payload)
                {
                    got.push(m);
                }
            });
            for m in got {
                let Some(&i) = self.by_mac.get(&m.chaddr) else {
                    continue;
                };
                match (m.kind, self.phase[i]) {
                    (MessageType::Offer, Phase::Discovering) => {
                        self.phase[i] = Phase::Requesting(
                            m.yiaddr,
                            m.server_id.unwrap_or(Ipv4Addr::new(10, 64, 0, 1)),
                        );
                        self.send(i);
                    }
                    (MessageType::Ack, Phase::Requesting(ip, _)) => {
                        self.phase[i] = Phase::Bound(ip)
                    }
                    (MessageType::Nak, _) => {
                        self.phase[i] = Phase::Discovering;
                        self.send(i);
                    }
                    _ => {}
                }
            }
            for i in 0..next {
                if matches!(self.phase[i], Phase::Discovering | Phase::Requesting(..))
                    && self.sent[i].elapsed() >= Duration::from_secs(2)
                {
                    // RFC 2131 §4.1: retransmit; a REQUEST that got no ACK
                    // starts over.
                    self.phase[i] = Phase::Discovering;
                    self.send(i);
                }
            }
            if self.bound() >= want {
                return true;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        false
    }
}

/// The RADIUS test server on two loopback sockets, in a thread.
struct Radius {
    srv: Arc<Mutex<TestServer>>,
    auth_port: u16,
    acct_port: u16,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Radius {
    fn start() -> Self {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        let acct = UdpSocket::bind("127.0.0.1:0").unwrap();
        let (auth_port, acct_port) = (
            sock.local_addr().unwrap().port(),
            acct.local_addr().unwrap().port(),
        );
        let srv = Arc::new(Mutex::new(TestServer::new(b"segredo", 7)));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (s2, stop2) = (srv.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            sock.set_nonblocking(true).unwrap();
            acct.set_nonblocking(true).unwrap();
            let mut buf = [0u8; 4096];
            let t0 = Instant::now();
            while !stop2.load(std::sync::atomic::Ordering::Relaxed) {
                let mut idle = true;
                for s in [&sock, &acct] {
                    while let Ok((n, from)) = s.recv_from(&mut buf) {
                        idle = false;
                        let r = s2.lock().unwrap().handle(
                            from,
                            &buf[..n],
                            t0.elapsed().as_millis() as u64,
                        );
                        if let Some(r) = r {
                            let _ = s.send_to(&r.bytes, r.to);
                        }
                    }
                }
                if idle {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        });
        Radius {
            srv,
            auth_port,
            acct_port,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Radius {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// The only test: the namespace is shared, so the stages run in order.
#[test]
fn ipoe_end_to_end() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    ip(
        None,
        &[
            "link", "add", "acc0", "type", "veth", "peer", "name", "cpe0",
        ],
    );
    ip(None, &["link", "set", "acc0", "up"]);
    ip(None, &["link", "set", "cpe0", "up"]);
    let dir = std::env::temp_dir().join(format!("g43f-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let daemon = daemon(&dir);
    let pid = daemon.0.id();
    for (id, p) in [
        (
            "ip.address.add",
            json!({"address": "10.64.0.1/16", "interface": "acc0"}),
        ),
        (
            "ip.pool.add",
            json!({"name": "subs", "ranges": "10.64.1.1-10.64.80.254"}),
        ),
        (
            "ppp.profile.add",
            json!({"name": "p50", "rate_limit": "50M/50M"}),
        ),
        (
            "ppp.secret.add",
            json!({"name": mac_text(mac(0)), "service": "ipoe", "profile": "p50"}),
        ),
        (
            "ip.dhcp-server.add",
            json!({"interface": "acc0", "address_pool": "subs", "ipoe": true, "ipoe_unknown": "reject", "conflict_detection": false, "lease_time": "1h", "client_rate_limit": 0}),
        ),
        (
            "ip.dhcp-server.network.add",
            json!({"address": "10.64.0.0/16", "gateway": "10.64.0.1"}),
        ),
    ] {
        ok(id, p);
    }
    wait_for("the ipoe service", || {
        ok("system.service.print", json!({}))
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["name"] == "ipoe" && r["state"] == "running")
    });

    // 1: the local list's subscriber; a stranger gets nothing.
    let mut one = Clients::new(0, 2);
    one.run(1, 30, 10);
    std::thread::sleep(Duration::from_secs(3));
    let rows = active();
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["service"], "ipoe");
    assert_eq!(rows[0]["name"], mac_text(mac(0)));
    assert_eq!(rows[0]["rate_limit"], "50M/50M");
    assert_eq!(one.bound(), 1, "the stranger got no address");
    let why = ok("ppp.why", json!({"mac": mac_text(mac(1))}));
    assert_eq!(why["last"]["reason"], "not-authorized", "{why}");
    drop(one);

    // 2: 10 000 subscribers authorized by RADIUS.
    let n = 10_000;
    let radius = Radius::start();
    {
        let mut srv = radius.srv.lock().unwrap();
        for k in 100..100 + n {
            let mut reply = AttrList::new();
            // Mikrotik-Rate-Limit (vendor 14988, type 8).
            reply.push_vsa(14988, 8, b"10M/50M").unwrap();
            if k == 100 {
                reply
                    .push_ipv4(attr::FRAMED_IP_ADDRESS, Ipv4Addr::new(10, 64, 99, 9))
                    .unwrap();
            }
            srv.add_user(&mac_text(mac(k)), "", reply);
        }
    }
    ok(
        "radius.add",
        json!({"address": "127.0.0.1", "authentication_port": radius.auth_port, "accounting_port": radius.acct_port, "service": "dhcp", "secret": "segredo"}),
    );
    ok(
        "ip.dhcp-server.set",
        json!({"id": "dhcp1", "use_radius": "yes"}),
    );
    std::thread::sleep(Duration::from_millis(1500));
    let rss0 = rss_kib(pid);
    let mut many = Clients::new(100, n);
    let t = Instant::now();
    assert!(many.run(n, 300, 20), "{} of {n} bound", many.bound());
    let took = t.elapsed().as_secs_f64();
    wait_for("10k active", || active().len() == n + 1);
    let rss1 = rss_kib(pid);
    println!(
        "MEASURED ipoe e2e: {n} RADIUS-authorized DHCP subscribers bound in {took:.2} s = {:.0} sessions/s (veth, debug build, no XDP); daemon RSS {rss0} → {rss1} KiB = {} B/session",
        n as f64 / took,
        (rss1.saturating_sub(rss0)) * 1024 / n as u64
    );
    let rows = active();
    let first = rows
        .iter()
        .find(|r| r["caller_id"] == mac_text(mac(100)))
        .unwrap();
    assert_eq!(first["address"], "10.64.99.9", "Framed-IP-Address");
    assert_eq!(first["radius"], true);
    assert_eq!(first["rate_limit"], "10M/50M");
    wait_for("an Accounting-Start each", || {
        radius
            .srv
            .lock()
            .unwrap()
            .accounting
            .iter()
            .filter(|a| a.status == 1)
            .count()
            >= n
    });

    // 3: RADIUS rejects (not in its users): no address, and why.
    let mut strangers = Clients::new(50_000, 5);
    strangers.run(5, 8, 5);
    assert_eq!(strangers.bound(), 0);
    let why = ok("ppp.why", json!({"name": mac_text(mac(50_000))}));
    assert_eq!(why["last"]["reason"], "rejected", "{why}");

    // 4: ppp.active.remove ends one: its lease goes and an Accounting-Stop.
    let id = first["id"].as_str().unwrap().to_owned();
    ok("ppp.active.remove", json!({"id": id}));
    wait_for("the removed session", || active().len() == n);
    wait_for("its Accounting-Stop", || {
        radius
            .srv
            .lock()
            .unwrap()
            .accounting
            .iter()
            .any(|a| a.status == 2)
    });
    drop(many);
    drop(radius);
    drop(daemon);
}

/// A lab for the screenshots: the daemon (its local token where the GUI
/// and CLI of this namespace look: `$COREROUTER_RUNTIME_DIR`), 40
/// subscribers (the first 30 by RADIUS, two of them rejected, ten from the
/// local list) kept bound for `IPOE_LAB_SECS`:
///
/// ```sh
/// COREROUTER_RUNTIME_DIR=/tmp/g43f-lab IPOE_LAB_SECS=600 COREROUTER_NETNS_TESTS=1 \
///     unshare --user --map-root-user --net -- cargo test -p corerouter-daemon \
///     --test netns_ipoe ipoe_lab -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn ipoe_lab() {
    if !in_netns() {
        return;
    }
    let secs: u64 = std::env::var("IPOE_LAB_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let run = std::path::PathBuf::from(std::env::var("COREROUTER_RUNTIME_DIR").unwrap());
    std::fs::create_dir_all(&run).unwrap();
    ip(None, &["link", "set", "lo", "up"]);
    ip(
        None,
        &[
            "link", "add", "acc0", "type", "veth", "peer", "name", "cpe0",
        ],
    );
    ip(None, &["link", "set", "acc0", "up"]);
    ip(None, &["link", "set", "cpe0", "up"]);
    let dir = run.join("cfg");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let mut c = in_ns(None, DAEMON);
    c.args([
        "--backend",
        "linux",
        "--no-discovery",
        "--manage",
        "acc0",
        "--control",
        "7979",
        "--config-dir",
    ])
    .arg(&dir)
    .stdout(Stdio::null())
    .stderr(std::fs::File::create(run.join("daemon.log")).unwrap());
    let _daemon = Kill(c.spawn().unwrap());
    let theirs = run.join("control-7979.token");
    let mine = token_file(None, &run);
    wait_for("the token", || theirs.exists());
    let _ = std::fs::remove_file(&mine);
    std::os::unix::fs::symlink(&theirs, &mine).unwrap();
    wait_for("the daemon", || {
        call(None, "interface.list", json!({})).is_ok()
    });
    let radius = Radius::start();
    {
        let mut srv = radius.srv.lock().unwrap();
        for k in 0..30 {
            if k == 7 || k == 21 {
                continue;
            }
            let mut reply = AttrList::new();
            reply
                .push_vsa(
                    14988,
                    8,
                    if k % 3 == 0 {
                        b"100M/300M".as_slice()
                    } else {
                        b"20M/50M".as_slice()
                    },
                )
                .unwrap();
            srv.add_user(&mac_text(mac(k)), "", reply);
        }
    }
    let mut steps = vec![
        (
            "ip.address.add",
            json!({"address": "10.64.0.1/16", "interface": "acc0"}),
        ),
        (
            "ip.pool.add",
            json!({"name": "subs", "ranges": "10.64.1.1-10.64.80.254"}),
        ),
        (
            "ppp.profile.add",
            json!({"name": "plano-30", "rate_limit": "30M/30M"}),
        ),
        (
            "radius.add",
            json!({"address": "127.0.0.1", "authentication_port": radius.auth_port, "accounting_port": radius.acct_port, "service": "dhcp", "secret": "segredo"}),
        ),
        (
            "ip.dhcp-server.add",
            json!({"interface": "acc0", "address_pool": "subs", "use_radius": "yes", "conflict_detection": false, "lease_time": "1h", "ipoe_keepalive": "5m"}),
        ),
        (
            "ip.dhcp-server.network.add",
            json!({"address": "10.64.0.0/16", "gateway": "10.64.0.1"}),
        ),
    ];
    for k in 30..40 {
        steps.push(("ppp.secret.add", json!({"name": mac_text(mac(k)), "service": "ipoe", "profile": "plano-30", "comment": format!("cliente {k}")})));
    }
    for (id, p) in steps {
        ok(id, p);
    }
    std::thread::sleep(Duration::from_millis(1500));
    let mut lab = Clients::new(0, 40);
    lab.run(38, 60, 2);
    println!(
        "LAB READY: {} bound, pid {}",
        lab.bound(),
        std::process::id()
    );
    lab.run(usize::MAX, secs, 1);
    drop(radius);
}

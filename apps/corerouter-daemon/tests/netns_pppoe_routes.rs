//! G4.3cd: a block routed to a business subscriber (`routes` of its
//! `/ppp secret`) through a `--backend linux` daemon, in a throwaway network
//! namespace, no root (slow path: `bng0`, no XDP):
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_pppoe_routes -- --test-threads 1
//! ```
//!
//! ```text
//!   daemon (BNG)                       this test (the CPEs)
//!   acc0 ──────────── veth ─────────── cpe0: "empresa" (203.0.113.8/29) and "casa"
//!   bng0 (dummy, slow path)
//!   wan0 198.51.100.1/24
//! ```
//!
//! A host of the /29 behind "empresa" pings wan0: the echo goes up from the
//! block (anti-spoofing lets it through), the reply comes back to the
//! right CPE by the route the session installed, and "casa" sees nothing.
//! After the logout the kernel route is gone (no blackhole left), and a
//! packet to the block reaches nobody.
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

use std::net::Ipv4Addr;
use std::process::Stdio;
use std::time::{Duration, Instant};

use common::*;
use corerouter_hal_linux::pppoe_io::PppoePort;
use corerouter_model::IfName;
use corerouter_proto_pppoe::client::{Client, ClientConfig, ClientEvent, ClientOutput};
use corerouter_proto_pppoe::wire::Mac;
use serde_json::{Value, json};

fn ok(command: &str, params: Value) -> Value {
    call(None, command, params).unwrap_or_else(|e| panic!("{command}: {e}"))
}

fn daemon(dir: &std::path::Path) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join("g43cd-routes.log")).unwrap();
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

fn mac_of(dev: &str) -> [u8; 6] {
    let out = std::process::Command::new("ip")
        .args(["-o", "link", "show", dev])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mac = text
        .split("link/ether ")
        .nth(1)
        .and_then(|t| t.split_whitespace().next())
        .unwrap();
    mac.parse::<corerouter_model::MacAddr>().unwrap().0
}

fn routes_to(prefix: &str) -> String {
    let out = std::process::Command::new("ip")
        .args(["-4", "route", "show", prefix])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn csum(b: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for ch in b.chunks(2) {
        s += u32::from(u16::from_be_bytes([ch[0], *ch.get(1).unwrap_or(&0)]));
    }
    while s >> 16 != 0 {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

fn icmp_echo(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0, 0x43, 0x44, 0, 1];
    icmp.extend_from_slice(b"bloco-roteado");
    let c = csum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    let mut ip = vec![0x45, 0, 0, 0, 0, 1, 0, 0, 64, 1, 0, 0];
    ip[2..4].copy_from_slice(&((20 + icmp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let c = csum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    ip.extend_from_slice(&icmp);
    ip
}

/// Two CPEs on cpe0: 0 = "empresa", 1 = "casa".
struct Cpes {
    port: PppoePort,
    clients: Vec<Client>,
    macs: Vec<[u8; 6]>,
    up: Vec<Option<u16>>,
    origin: Instant,
    out: ClientOutput,
    /// IPv4 packets (PPP 0x0021) each CPE got.
    got: Vec<Vec<Vec<u8>>>,
}

impl Cpes {
    fn new(users: &[(&str, &str)]) -> Self {
        let port = PppoePort::open(&"cpe0".parse::<IfName>().unwrap(), &[], true).unwrap();
        let mut clients = Vec::new();
        let mut macs = Vec::new();
        for (i, (u, p)) in users.iter().enumerate() {
            let mac = [0x02, 0x30, 0, 0, i as u8, 0x01];
            let cfg = ClientConfig {
                mac: Mac(mac),
                ifindex: port.ifindex(),
                username: u.as_bytes().to_vec(),
                password: (*p).to_owned(),
                discovery_timeout_ms: 1000,
                discovery_attempts: 30,
                keepalive_interval_ms: 0,
                ..ClientConfig::default()
            };
            clients.push(Client::new(cfg, [0x33 + i as u8; 32]));
            macs.push(mac);
        }
        let n = users.len();
        Self {
            port,
            clients,
            macs,
            up: vec![None; n],
            origin: Instant::now(),
            out: ClientOutput::new(),
            got: vec![Vec::new(); n],
        }
    }

    fn now(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }

    fn send_out(&mut self) {
        for (_, f) in self.out.frames() {
            let _ = self.port.send(f);
        }
        self.out.clear();
    }

    fn start(&mut self) {
        for i in 0..self.clients.len() {
            let now = self.now();
            self.clients[i].start(now, &mut self.out);
            self.send_out();
        }
    }

    fn run_until(&mut self, secs: u64, mut done: impl FnMut(&Self) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            let now = self.now();
            let mut frames: Vec<Vec<u8>> = Vec::new();
            self.port.recv(|f| frames.push(f.to_vec())).unwrap();
            for f in frames {
                let Some(c) = self.macs.iter().position(|m| f[..6] == m[..]) else {
                    continue;
                };
                if f.len() > 22 && f[12..14] == [0x88, 0x64] && f[20..22] == [0x00, 0x21] {
                    self.got[c].push(f[22..].to_vec());
                    continue;
                }
                self.clients[c].handle_frame(now, &f, &mut self.out);
                self.note(c);
            }
            for c in 0..self.clients.len() {
                if self.clients[c].next_deadline().is_some_and(|d| d <= now) {
                    self.clients[c].handle_timers(now, &mut self.out);
                    self.note(c);
                }
            }
            if done(self) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        false
    }

    fn note(&mut self, c: usize) {
        for ev in self.out.events.drain(..) {
            match ev {
                ClientEvent::Up { sid, .. } => self.up[c] = Some(sid),
                ClientEvent::Down { .. } => self.up[c] = None,
            }
        }
        self.send_out();
    }

    /// Send IPv4 `pkt` from CPE `c` in its session.
    fn send_ip(&mut self, c: usize, pkt: &[u8]) {
        let sid = self.up[c].unwrap();
        let mut f = Vec::new();
        f.extend_from_slice(&mac_of("acc0"));
        f.extend_from_slice(&self.macs[c]);
        f.extend_from_slice(&[0x88, 0x64, 0x11, 0x00]);
        f.extend_from_slice(&sid.to_be_bytes());
        f.extend_from_slice(&((pkt.len() + 2) as u16).to_be_bytes());
        f.extend_from_slice(&[0x00, 0x21]);
        f.extend_from_slice(pkt);
        self.port.send(&f).unwrap();
    }
}

/// An ICMP echo reply to `dst` among what CPE `c` got.
fn has_reply(got: &[Vec<u8>], dst: Ipv4Addr) -> bool {
    got.iter()
        .any(|p| p.len() > 20 && p[9] == 1 && p[16..20] == dst.octets() && p[20] == 0)
}

/// The only test: the namespace is shared.
#[test]
fn a_routed_block_reaches_its_subscriber_and_leaves_with_it() {
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
    ip(None, &["link", "add", "wan0", "type", "dummy"]);
    ip(None, &["addr", "add", "198.51.100.1/24", "dev", "wan0"]);
    ip(None, &["link", "set", "wan0", "up"]);
    let dir = std::env::temp_dir().join(format!("g43cd-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let _d = daemon(&dir);
    ok(
        "ip.pool.add",
        json!({"name": "clientes", "ranges": "100.64.0.0/24"}),
    );
    ok(
        "ppp.profile.set",
        json!({"id": "default", "remote_address": "clientes"}),
    );
    ok(
        "ppp.secret.add",
        json!({"name": "empresa", "password": "e1", "routes": "203.0.113.8/29"}),
    );
    ok("ppp.secret.add", json!({"name": "casa", "password": "c1"}));
    ok(
        "interface.pppoe-server.server.add",
        json!({"interface": "acc0", "padi_limit": 0, "mac_padi_limit": 0, "new_session_rate": 0}),
    );
    let mut cpes = Cpes::new(&[("empresa", "e1"), ("casa", "c1")]);
    cpes.start();
    assert!(
        cpes.run_until(30, |c| c.up.iter().all(Option::is_some)),
        "both up: {:?}",
        cpes.up
    );

    // The session holds the block: in ppp.active, ppp.why and the kernel.
    wait_for("the routed block", || {
        routes_to("203.0.113.8/29").contains("bng0")
    });
    let rows = ok("ppp.active.list", json!({"find": "203.0.113"}))["rows"].clone();
    assert_eq!(rows.as_array().unwrap().len(), 1, "{rows}");
    assert_eq!(rows[0]["name"], "empresa");
    assert_eq!(rows[0]["routes"][0]["route"], "203.0.113.8/29");
    assert_eq!(rows[0]["routes"][0]["origin"], "secret");
    let why = ok("ppp.why", json!({"name": "empresa"}));
    assert_eq!(why["routes"][0]["route"], "203.0.113.8/29", "{why}");

    // A host of the block pings wan0: up from the block, the reply back to
    // "empresa" only.
    let host = Ipv4Addr::new(203, 0, 113, 10);
    let wan = Ipv4Addr::new(198, 51, 100, 1);
    let mut got = false;
    for _ in 0..20 {
        cpes.send_ip(0, &icmp_echo(host, wan));
        if cpes.run_until(1, |c| has_reply(&c.got[0], host)) {
            got = true;
            break;
        }
    }
    assert!(
        got,
        "the echo reply to {host} came back through the routed block"
    );
    assert!(
        !has_reply(&cpes.got[1], host),
        "the other subscriber saw nothing"
    );
    // A source outside the block from "empresa": dropped (anti-spoofing).
    let stranger = Ipv4Addr::new(203, 0, 113, 77);
    cpes.send_ip(0, &icmp_echo(stranger, wan));
    assert!(
        !cpes.run_until(2, |c| has_reply(&c.got[0], stranger)),
        "spoofed source answered"
    );

    // Logout: the route goes with the session (no blackhole), and the
    // block reaches nobody.
    let id = rows[0]["id"].as_str().unwrap().to_owned();
    ok("ppp.active.remove", json!({"id": id}));
    assert!(cpes.run_until(10, |c| c.up[0].is_none()), "terminated");
    wait_for("the route gone", || routes_to("203.0.113.8/29").is_empty());
    cpes.got = vec![Vec::new(); 2];
    let sock = std::net::UdpSocket::bind("198.51.100.1:0").unwrap();
    let _ = sock.send_to(b"x", "203.0.113.10:9");
    cpes.run_until(2, |_| false);
    assert!(
        cpes.got.iter().all(Vec::is_empty),
        "nobody gets the block after the logout"
    );
    let h = ok("ppp.history", json!({"name": "empresa", "limit": 1}));
    assert_eq!(h[0]["routes"][0]["route"], "203.0.113.8/29", "{h}");
}

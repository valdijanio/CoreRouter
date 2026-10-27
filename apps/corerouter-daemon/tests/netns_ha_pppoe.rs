//! G4.3h phase 1: a redundant pair of `--backend linux` daemons serving
//! real `proto-pppoe` CPEs on one access L2, in throwaway namespaces, no
//! root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_ha_pppoe -- --test-threads 1 --nocapture
//! ```
//!
//! ```text
//!   A (here)                br0 (the access L2)              B (namespace_b)
//!   acc0 ── acc0-p ─────────┤├───────── accb-p ── acc0
//!                     cpe0-p ┘└ the CPEs (cpe0)
//!   sync0 10.9.0.1 ────────────── veth ──────────────── sync0 10.9.0.2
//!   gw0 10.99.0.1 (witness)                              gw0 10.99.0.1
//! ```
//!
//! Only the active node answers: every CPE comes up on A, none on B.
//! Then A dies: B takes over, the CPEs' keepalive gets B's PADT for a
//! session it does not know, and they redial on B (stateless: phase 1).
//! The time until every CPE is up again is printed (`docs/bng-ha.md`).
//!
//! G4.3hb: after a switchover, a RADIUS server that still sends its CoA
//! and Disconnect-Request to A (now the standby) gets them applied by B
//! through the sync link, and A's answer says what B did.
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
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use common::*;
use corerouter_hal_linux::pppoe_io::PppoePort;
use corerouter_model::IfName;
use corerouter_proto_pppoe::client::{Client, ClientConfig, ClientEvent, ClientOutput};
use corerouter_proto_pppoe::layers::AuthSet;
use corerouter_proto_pppoe::wire::Mac;
use serde_json::{Value, json};

const SECRET: &str = "segredo-do-par-de-teste";
const VMAC: [u8; 6] = [0x02, 0x43, 0x52, 0x48, 0x41, 0x01];

fn daemon(netns: Option<u32>, dir: &Path, log: &str) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join(log)).unwrap();
    let mut c = in_ns(netns, DAEMON);
    c.args([
        "--backend",
        "linux",
        "--no-discovery",
        "--manage",
        "acc0,sync0",
        "--control",
        "7979",
        "--config-dir",
    ])
    .arg(dir)
    .arg("--token-file")
    .arg(token_file(netns, dir))
    .env("RUST_LOG", "info")
    .stdout(Stdio::null())
    .stderr(log);
    let k = Kill(c.spawn().unwrap());
    wait_for("the daemon and its ports", || {
        call(netns, "interface.list", json!({})).is_ok_and(|v| v.to_string().contains("\"acc0\""))
    });
    k
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("g43h-pppoe-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn ok(netns: Option<u32>, command: &str, params: Value) -> Value {
    call(netns, command, params).unwrap_or_else(|e| panic!("{command} in {netns:?}: {e}"))
}

/// The same config on both nodes (one login for every CPE: the default
/// profile has only-one=no).
fn configure(netns: Option<u32>, peer: &str, priority: u32, mode: &str) {
    ok(
        netns,
        "ip.pool.add",
        json!({"name": "clientes", "ranges": "100.64.0.0/16"}),
    );
    ok(
        netns,
        "ppp.profile.set",
        json!({"id": "default", "remote_address": "clientes"}),
    );
    ok(
        netns,
        "ppp.secret.add",
        json!({"name": "cpe", "password": "senha"}),
    );
    ok(
        netns,
        "interface.pppoe-server.server.add",
        json!({"interface": "acc0", "padi_limit": 0, "mac_padi_limit": 0, "new_session_rate": 0, "keepalive_timeout": 10}),
    );
    ok(
        netns,
        "ppp.redundancy.set",
        json!({
            "enabled": true, "mode": mode, "peer": format!("{peer}:8730"), "secret": SECRET,
            "witness": ["10.99.0.1"], "interfaces": ["acc0"], "priority": priority, "init_hold": 2
        }),
    );
}

fn active(netns: Option<u32>) -> usize {
    call(netns, "ppp.active.list", json!({"limit": 1}))
        .ok()
        .and_then(|v| v["total"].as_u64())
        .unwrap_or(0) as usize
}

fn role(netns: Option<u32>) -> String {
    call(netns, "ppp.redundancy.monitor", json!({}))
        .ok()
        .and_then(|v| v["role"].as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// The CPEs: `proto-pppoe` clients with their own keepalive (1 s × 3), on
/// one AF_PACKET port; a CPE whose session ends dials again.
struct Cpes {
    port: PppoePort,
    clients: Vec<Client>,
    by_mac: HashMap<[u8; 6], usize>,
    up: Vec<Option<[u8; 6]>>,
    origin: Instant,
    out: ClientOutput,
    downs: usize,
}

impl Cpes {
    fn new(n: usize) -> Self {
        let port = PppoePort::open(&"cpe0".parse::<IfName>().unwrap(), &[], true).unwrap();
        let mut clients = Vec::new();
        let mut by_mac = HashMap::new();
        for i in 0..n {
            let mac = [0x02, 0x20, (i >> 16) as u8, (i >> 8) as u8, i as u8, 0x01];
            let cfg = ClientConfig {
                mac: Mac(mac),
                ifindex: port.ifindex(),
                username: b"cpe".to_vec(),
                password: "senha".into(),
                auth: AuthSet::routeros_default(),
                discovery_timeout_ms: 1000,
                discovery_attempts: 60,
                discovery_jitter_pct: 25,
                keepalive_interval_ms: 1000,
                keepalive_misses: 3,
                ..ClientConfig::default()
            };
            let mut seed = [0x5au8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            clients.push(Client::new(cfg, seed));
            by_mac.insert(mac, i);
        }
        Self {
            port,
            clients,
            by_mac,
            up: vec![None; n],
            origin: Instant::now(),
            out: ClientOutput::new(),
            downs: 0,
        }
    }

    fn now(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }

    fn start_all(&mut self) {
        for i in 0..self.clients.len() {
            let now = self.now();
            self.clients[i].start(now, &mut self.out);
            self.note(i);
        }
    }

    fn run_until(&mut self, secs: u64, mut done: impl FnMut(&Self) -> bool) -> Option<Duration> {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(secs) {
            let now = self.now();
            let mut frames: Vec<Vec<u8>> = Vec::new();
            self.port.recv(|f| frames.push(f.to_vec())).unwrap();
            for f in frames {
                let mut dst = [0u8; 6];
                dst.copy_from_slice(&f[..6]);
                let Some(&c) = self.by_mac.get(&dst) else {
                    continue;
                };
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
                return Some(start.elapsed());
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        None
    }

    fn note(&mut self, c: usize) {
        let mut again = false;
        for ev in self.out.events.drain(..) {
            match ev {
                ClientEvent::Up { ac_mac, .. } => self.up[c] = Some(ac_mac.0),
                ClientEvent::Down { .. } => {
                    self.up[c] = None;
                    self.downs += 1;
                    again = true;
                }
            }
        }
        for (_, f) in self.out.frames() {
            let _ = self.port.send(f);
        }
        self.out.clear();
        if again {
            let now = self.now();
            self.clients[c].start(now, &mut self.out);
            for (_, f) in self.out.frames() {
                let _ = self.port.send(f);
            }
            self.out.clear();
        }
    }

    fn ups(&self) -> usize {
        self.up.iter().filter(|u| u.is_some()).count()
    }
}

/// Not a test: run inside B by `call`.
#[test]
fn query_helper() {
    common::query_helper();
}

/// The pair, the CPEs up on A; returns what the takeover test needs.
fn pair(mode: &str) -> (Kill, Kill, Kill, Cpes, u32, usize) {
    let n: usize = std::env::var("COREROUTER_HA_CPES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);
    ip(None, &["link", "set", "lo", "up"]);
    let holder = namespace_b();
    let b = holder.0.id();
    let pid = b.to_string();
    ip(Some(b), &["link", "set", "lo", "up"]);
    ip(None, &["link", "add", "br0", "type", "bridge"]);
    ip(None, &["link", "set", "br0", "up"]);
    ip(
        None,
        &[
            "link", "add", "acc0", "type", "veth", "peer", "name", "acc0-p",
        ],
    );
    ip(
        None,
        &[
            "link", "add", "cpe0", "type", "veth", "peer", "name", "cpe0-p",
        ],
    );
    ip(
        None,
        &[
            "link", "add", "accb-p", "type", "veth", "peer", "name", "acc0", "netns", &pid,
        ],
    );
    for p in ["acc0-p", "cpe0-p", "accb-p"] {
        ip(None, &["link", "set", p, "master", "br0"]);
        ip(None, &["link", "set", p, "up"]);
    }
    ip(None, &["link", "set", "acc0", "up"]);
    ip(None, &["link", "set", "cpe0", "up"]);
    ip(Some(b), &["link", "set", "acc0", "up"]);
    ip(
        None,
        &[
            "link", "add", "sync0", "type", "veth", "peer", "name", "sync0", "netns", &pid,
        ],
    );
    ip(None, &["link", "set", "sync0", "up"]);
    ip(Some(b), &["link", "set", "sync0", "up"]);
    ip(None, &["addr", "add", "10.9.0.1/24", "dev", "sync0"]);
    ip(Some(b), &["addr", "add", "10.9.0.2/24", "dev", "sync0"]);
    for ns in [None, Some(b)] {
        ip(ns, &["link", "add", "gw0", "type", "dummy"]);
        ip(ns, &["addr", "add", "10.99.0.1/24", "dev", "gw0"]);
        ip(ns, &["link", "set", "gw0", "up"]);
    }

    let (dir_a, dir_b) = (temp_dir("a"), temp_dir("b"));
    let a = daemon(None, &dir_a, "g43h-pppoe-a.log");
    let b_daemon = daemon(Some(b), &dir_b, "g43h-pppoe-b.log");
    configure(None, "10.9.0.2", 200, mode);
    configure(Some(b), "10.9.0.1", 100, mode);
    wait_for("A active, B standby", || {
        role(None) == "active" && role(Some(b)) == "standby"
    });

    let mut cpes = Cpes::new(n);
    cpes.start_all();
    let t = cpes
        .run_until(120, |c| c.ups() == n)
        .expect("every CPE up on A");
    eprintln!("{n} CPEs up on A in {t:?}");
    assert!(
        cpes.up.iter().all(|u| *u == Some(VMAC)),
        "every session on the virtual MAC"
    );
    assert_eq!(active(None), n);
    assert_eq!(active(Some(b)), 0, "the standby answered nobody");
    // Steady state: the standby sends nothing (a PADT of its own to these
    // sessions would end them), the CPEs' keepalive is answered by A.
    cpes.run_until(5, |_| false);
    assert_eq!(cpes.downs, 0, "no CPE fell while A serves");

    (holder, a, b_daemon, cpes, b, n)
}

/// Removes what [`pair`] made in this namespace (B's goes with its holder).
fn teardown() {
    for l in ["br0", "acc0", "cpe0", "accb-p", "sync0", "gw0"] {
        let _ = in_ns(None, "ip").args(["link", "del", l]).output();
    }
}

/// The only test: the namespace is shared, so the two modes run in order.
#[test]
fn a_pair_serves_pppoe_stateless_and_hot_standby() {
    if !in_netns() {
        return;
    }
    stateless_the_cpes_redial_on_the_new_active();
    teardown();
    hot_standby_keeps_every_session_when_the_active_dies();
    teardown();
    coa_to_the_old_active_reaches_the_new_one();
}

fn stateless_the_cpes_redial_on_the_new_active() {
    let (_holder, a, _b_daemon, mut cpes, b, n) = pair("stateless");
    // A dies: B takes over; the CPEs redial on B.
    drop(a);
    let t = cpes
        .run_until(180, |c| c.ups() == n && c.downs >= n)
        .expect("every CPE back, on B");
    eprintln!(
        "{n} CPEs back on B {t:?} after A died ({} downs)",
        cpes.downs
    );
    assert_eq!(role(Some(b)), "active");
    assert_eq!(active(Some(b)), n);
    assert!(
        cpes.up.iter().all(|u| *u == Some(VMAC)),
        "the same AC MAC on B"
    );
}

fn hot_standby_keeps_every_session_when_the_active_dies() {
    let (_holder, a, _b_daemon, mut cpes, b, n) = pair("hot-standby");
    // The standby's replica holds every session.
    wait_for("the replica", || {
        call(Some(b), "ppp.redundancy.monitor", json!({}))
            .is_ok_and(|m| m["sync"]["synced"].as_u64() == Some(n as u64) && m["in_sync"] == true)
    });
    drop(a);
    let killed = Instant::now();
    wait_for("B active", || role(Some(b)) == "active");
    let took = killed.elapsed();
    // Ten seconds of keepalive (1 s × 3 on the CPEs) on B: nobody falls.
    cpes.run_until(10, |_| false);
    eprintln!(
        "{n} sessions on B {took:?} after A died; {} CPEs went down",
        cpes.downs
    );
    assert_eq!(cpes.downs, 0, "no CPE noticed");
    assert_eq!(cpes.ups(), n);
    assert_eq!(active(Some(b)), n, "B holds every session");
    let h = call(Some(b), "ppp.history", json!({"limit": 5})).unwrap();
    assert!(h.to_string().contains("takeover"), "{h}");
}

const COA_SECRET: &str = "segredo-do-coa";

/// The RADIUS server's CoA client: 127.0.0.1 (a `/radius` entry on both
/// nodes), sending to A's `/radius incoming` port.
fn radius_incoming(netns: Option<u32>) {
    ok(
        netns,
        "radius.add",
        json!({"address": "127.0.0.1", "service": ["ppp"], "secret": COA_SECRET}),
    );
    ok(
        netns,
        "radius.incoming.set",
        json!({"accept": true, "port": 3799}),
    );
}

/// One CoA (rate) or Disconnect for `ip`: the reply's code and Error-Cause,
/// and how long it took.
fn coa_to_a(
    sock: &std::net::UdpSocket,
    id: u8,
    ip: std::net::Ipv4Addr,
    rate: Option<&str>,
) -> (corerouter_proto_radius::packet::Code, Option<u32>, Duration) {
    use corerouter_proto_radius::dynauth::{RequestKind, build_request};
    use corerouter_proto_radius::packet::{AttrList, Packet, PushAttr, attr};
    let mut l = AttrList::new();
    l.push_ipv4(attr::FRAMED_IP_ADDRESS, ip).unwrap();
    let kind = match rate {
        Some(r) => {
            l.push_vsa(14988, 8, r.as_bytes()).unwrap();
            RequestKind::Coa
        }
        None => RequestKind::Disconnect,
    };
    let req = build_request(kind, id, &l, COA_SECRET.as_bytes(), true);
    let t = Instant::now();
    sock.send_to(&req, ("127.0.0.1", 3799)).unwrap();
    let mut buf = [0u8; 4096];
    let (n, _) = sock.recv_from(&mut buf).expect("no answer to the CoA");
    let took = t.elapsed();
    let p = Packet::parse(&buf[..n]).unwrap();
    (p.code(), p.attr_u32(attr::ERROR_CAUSE), took)
}

fn addresses(netns: Option<u32>) -> Vec<(std::net::Ipv4Addr, Value)> {
    let l = ok(netns, "ppp.active.list", json!({}));
    l["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| Some((r["address"].as_str()?.parse().ok()?, r.clone())))
        .collect()
}

fn coa_to_the_old_active_reaches_the_new_one() {
    use corerouter_proto_radius::packet::Code;
    let (_holder, _a, _b_daemon, mut cpes, b, n) = pair("hot-standby");
    radius_incoming(None);
    radius_incoming(Some(b));
    wait_for("both listening for CoA", || {
        [None, Some(b)].iter().all(|ns| {
            call(*ns, "radius.incoming.get", json!({})).is_ok_and(|v| v["listening"].is_string())
        })
    });
    wait_for("the replica", || {
        call(Some(b), "ppp.redundancy.monitor", json!({}))
            .is_ok_and(|m| m["sync"]["synced"].as_u64() == Some(n as u64) && m["in_sync"] == true)
    });
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let on_a = addresses(None);
    let (ip0, _) = on_a[0].clone();
    // On the active: applied there.
    let (code, _, local) = coa_to_a(&sock, 1, ip0, Some("7M/7M"));
    assert_eq!(code, Code::CoaAck);

    // Switchover: B active, A the standby; the server still knows A.
    ok(None, "ppp.redundancy.switchover", json!({}));
    wait_for("B active, A standby", || {
        role(Some(b)) == "active" && role(None) == "standby"
    });
    wait_for("B holds every session", || active(Some(b)) == n);
    cpes.run_until(3, |_| false);
    // CoA to A: B applies it, A answers ACK.
    let on_b = addresses(Some(b));
    let mut times = Vec::new();
    for (k, (ip, _)) in on_b.iter().take(20).enumerate() {
        let (code, cause, t) = coa_to_a(&sock, 10 + k as u8, *ip, Some("9M/9M"));
        assert_eq!(
            (code, cause),
            (Code::CoaAck, None),
            "CoA {k} through the peer"
        );
        times.push(t);
    }
    times.sort();
    let rate_on_b = addresses(Some(b))
        .into_iter()
        .filter(|(ip, _)| on_b.iter().take(20).any(|(x, _)| x == ip))
        .filter(|(_, r)| r["rate_limit"] == "9M/9M")
        .count();
    assert_eq!(rate_on_b, 20.min(on_b.len()), "B applied the rate");
    // An address nobody holds: NAK 503, through the peer.
    let (code, cause, _) = coa_to_a(&sock, 40, "198.18.0.1".parse().unwrap(), None);
    assert_eq!((code, cause), (Code::DisconnectNak, Some(503)));
    // A Disconnect through A ends the session on B.
    let (ip_end, _) = on_b[0].clone();
    let (code, cause, _) = coa_to_a(&sock, 41, ip_end, None);
    assert_eq!((code, cause), (Code::DisconnectAck, None));
    wait_for("the session gone from B", || {
        !addresses(Some(b)).iter().any(|(ip, _)| *ip == ip_end)
    });
    let inc = ok(None, "radius.incoming.get", json!({}));
    eprintln!(
        "CoA on the active {local:?}; to the old active, through the peer: median {:?}, max {:?} (20); A forwarded {} answered {}",
        times[times.len() / 2],
        times[times.len() - 1],
        inc["forwarded"],
        inc["forward_answered"]
    );
    assert_eq!(inc["forwarded"], 22, "{inc}");
}

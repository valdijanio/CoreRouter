//! G4.3h: the redundant BNG pair under BNG Blaster (`cargo xtask bng-lab
//! --only ha`). Two `--backend linux` daemons in hot standby, BNG
//! Blaster's subscribers on one access L2, a RADIUS test server both reach;
//! the active one loses power (every port down at once), and the lab
//! measures what the subscribers and the RADIUS server saw.
//!
//! ```text
//!   A (here)                     br0 (access L2)            Bl (BNG Blaster)
//!   acc0 ── acc0-p ──────────────┤├──── cpe0-p ── cpe0
//!                                ┤├──── accc-p ── acc0      C (the standby)
//!   wan0 .1 ── wan0-p ───── br1 (uplink) ─ blnet-p ── blnet .2 (Bl)
//!                                ┤ ─── wanc-p ── wan0 .3    (C)
//!   sync0 10.9.0.1 ─────────── veth ───────────── sync0 10.9.0.2 (C)
//!   rad0 10.8.0.1 (RADIUS) ─── veth ───────────── rad0 10.8.0.2 (C)
//!   gw0 10.99.0.1 (witness)                        gw0 10.99.0.1 (C)
//! ```
//!
//! Per scale (`BNG_LAB_HA_SCALES`, default 10000): every subscriber up on
//! A, the replica complete on C; A's ports down; then
//! - **sessions lost**: BNG Blaster's flapped sessions (target 0), and
//!   C's active table;
//! - **traffic back**: from the cut until C counts the subscribers'
//!   upstream bytes again (1 pps each, BNG Blaster session traffic);
//!   downstream rides the routing protocol announcing the pool, outside
//!   this lab;
//! - **accounting**: one Start per session, no Stop, and C's Interim with
//!   the same Acct-Session-Id after the takeover.
//!
//! Results: `$BNG_LAB_OUT/ha-summary.md`. Helpers may unwrap/panic.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use corerouter_proto_radius::packet::AttrList;
use corerouter_proto_radius::testserver::TestServer;
use serde_json::{Value, json};

const PER_PORT: usize = 50_000;
/// Up to this many sessions every one carries traffic (1 pps each way);
/// above, only the sample measured: the slow path (no XDP without root) is
/// one thread, and 200 000 pps through it would drown the LCP echoes, which
/// is not what this lab measures (`bng_lab.rs` samples the same way).
const SAMPLE_ALL: usize = 2000;
const SECRET: &str = "lab-segredo";
const PAIR_SECRET: &str = "segredo-do-par-do-laboratorio";

fn holder() -> Kill {
    let k = Kill(
        Command::new("unshare")
            .args(["--net", "--", "sleep", "86400"])
            .spawn()
            .unwrap(),
    );
    let here = netns_of(std::process::id());
    wait_for("a namespace", || {
        netns_of(k.0.id()).is_some_and(|ns| Some(ns) != here)
    });
    k
}

fn sysctl(ns: Option<u32>, key: &str, v: &str) {
    let _ = in_ns(ns, "sh")
        .args(["-c", &format!("echo {v} > /proc/sys/{key}")])
        .status();
}

/// A RADIUS test server on 10.8.0.1 that keeps every accounting record.
struct Radius {
    stop: Arc<AtomicBool>,
    auth: u16,
    acct: u16,
    log: Arc<Mutex<Vec<(u32, String, String)>>>,
}

impl Radius {
    fn start(users: usize) -> Self {
        let sock = UdpSocket::bind("10.8.0.1:0").unwrap();
        let acct = UdpSocket::bind("10.8.0.1:0").unwrap();
        let (auth, acct_port) = (
            sock.local_addr().unwrap().port(),
            acct.local_addr().unwrap().port(),
        );
        let mut srv = TestServer::new(SECRET.as_bytes(), 7);
        for i in 1..=users {
            srv.add_user(&format!("rad{i}"), "test", AttrList::new());
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stop2 = stop.clone();
        let log = Arc::new(Mutex::new(Vec::new()));
        let log2 = log.clone();
        std::thread::spawn(move || {
            sock.set_read_timeout(Some(Duration::from_millis(5)))
                .unwrap();
            acct.set_read_timeout(Some(Duration::from_millis(5)))
                .unwrap();
            let mut buf = [0u8; 4096];
            let t0 = Instant::now();
            while !stop2.load(Ordering::Relaxed) {
                for s in [&sock, &acct] {
                    while let Ok((n, from)) = s.recv_from(&mut buf) {
                        if let Some(r) =
                            srv.handle(from, &buf[..n], t0.elapsed().as_millis() as u64)
                        {
                            let _ = s.send_to(&r.bytes, r.to);
                        }
                    }
                }
                if !srv.accounting.is_empty() {
                    let mut l = log2.lock().unwrap();
                    for a in srv.accounting.drain(..) {
                        l.push((a.status, a.session_id, a.from.ip().to_string()));
                    }
                }
            }
        });
        Self {
            stop,
            auth,
            acct: acct_port,
            log,
        }
    }

    /// (status, Acct-Session-Id, from) of every record so far.
    fn records(&self) -> Vec<(u32, String, String)> {
        self.log.lock().unwrap().clone()
    }
}

impl Drop for Radius {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// BNG Blaster in its namespace.
struct Blaster {
    child: Child,
    sock: PathBuf,
}

impl Blaster {
    fn start(ns: u32, bin: &Path, out: &Path, n: usize) -> Self {
        let ports = n.div_ceil(PER_PORT).max(1);
        let access: Vec<Value> = (0..ports)
            .map(|i| json!({"interface": format!("cpe{i}"), "type": "pppoe", "vlan-mode": "N:1", "session-limit": PER_PORT}))
            .collect();
        let cfg = json!({
            "interfaces": {
                "tx-interval": 1.0,
                "rx-interval": 1.0,
                "network": {"interface": "blnet", "address": "198.51.100.2/24", "gateway": "198.51.100.1"},
                "access": access,
            },
            "sessions": {"count": n, "max-outstanding": 4000, "start-rate": 5000, "stop-rate": 10000, "reconnect": true},
            "pppoe": {"reconnect": true, "discovery-timeout": 3, "discovery-retry": 30, "host-uniq": true},
            "ppp": {
                "mru": 1492,
                "authentication": {"username": "rad{session-global}", "password": "test", "timeout": 5, "retry": 30, "protocol": "CHAP"},
                "lcp": {"conf-request-timeout": 2, "conf-request-retry": 30, "keepalive-interval": 5, "keepalive-retry": 3},
                "ipcp": {"enable": true, "request-dns1": false, "request-dns2": false},
                "ip6cp": {"enable": false},
            },
            "dhcpv6": {"enable": false},
            "session-traffic": {"autostart": n <= SAMPLE_ALL, "ipv4-pps": 1},
        });
        let path = out.join(format!("ha-{n}.json"));
        std::fs::write(&path, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
        let sock = PathBuf::from(format!("/tmp/crha-{}-{n}.sock", std::process::id()));
        let _ = std::fs::remove_file(&sock);
        let log = std::fs::File::create(out.join(format!("ha-{n}-blaster.out"))).unwrap();
        let child = in_ns(Some(ns), &bin.to_string_lossy())
            .arg("-C")
            .arg(&path)
            .arg("-S")
            .arg(&sock)
            .args(["-l", "error"])
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        let t = Instant::now();
        while !sock.exists() && t.elapsed() < Duration::from_secs(20) {
            std::thread::sleep(Duration::from_millis(50));
        }
        Self { child, sock }
    }

    fn cmd(&self, req: Value) -> Value {
        let Ok(mut s) = UnixStream::connect(&self.sock) else {
            return Value::Null;
        };
        let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = s.write_all(req.to_string().as_bytes());
        let mut buf = String::new();
        let _ = s.read_to_string(&mut buf);
        serde_json::from_str(&buf).unwrap_or(Value::Null)
    }

    fn counters(&self) -> (u64, u64) {
        let v = self.cmd(json!({"command": "session-counters"}));
        let c = &v["session-counters"];
        (
            c["sessions-established"].as_u64().unwrap_or(0),
            c["sessions-flapped"].as_u64().unwrap_or(0),
        )
    }
}

impl Drop for Blaster {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.sock);
    }
}

fn daemon(ns: Option<u32>, dir: &Path, log: &Path) -> Kill {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let mut c = in_ns(ns, DAEMON);
    c.args([
        "--backend",
        "linux",
        "--no-discovery",
        "--manage",
        "acc*,wan0,sync0,rad0",
        "--control",
        "7979",
        "--config-dir",
    ])
    .arg(dir)
    .arg("--token-file")
    .arg(token_file(ns, dir))
    .env("RUST_LOG", "warn")
    .stdout(Stdio::null())
    .stderr(std::fs::File::create(log).unwrap());
    let k = Kill(c.spawn().unwrap());
    wait_for("a daemon", || {
        call(ns, "interface.list", json!({})).is_ok_and(|v| v.to_string().contains("\"acc0\""))
    });
    k
}

fn ok(ns: Option<u32>, command: &str, params: Value) -> Value {
    call(ns, command, params).unwrap_or_else(|e| panic!("{command} in {ns:?}: {e}"))
}

fn configure(ns: Option<u32>, uplink: &str, peer: &str, priority: u32, ports: usize, r: &Radius) {
    ok(
        ns,
        "ip.address.add",
        json!({"address": uplink, "interface": "wan0"}),
    );
    ok(
        ns,
        "ip.pool.add",
        json!({"name": "clientes", "ranges": "100.64.0.0/14"}),
    );
    ok(
        ns,
        "ppp.profile.set",
        json!({"id": "default", "remote_address": "clientes"}),
    );
    ok(
        ns,
        "radius.add",
        json!({"address": "10.8.0.1", "secret": SECRET, "service": "ppp", "authentication_port": r.auth, "accounting_port": r.acct}),
    );
    ok(
        ns,
        "ppp.aaa.set",
        json!({"use_radius": true, "accounting": true, "interim_update": 300}),
    );
    for i in 0..ports {
        ok(
            ns,
            "interface.pppoe-server.server.add",
            json!({"interface": format!("acc{i}"), "authentication": "chap,pap", "padi_limit": 0, "mac_padi_limit": 0, "new_session_rate": 0, "keepalive_timeout": 30}),
        );
    }
    let ifs: Vec<String> = (0..ports).map(|i| format!("acc{i}")).collect();
    ok(
        ns,
        "ppp.redundancy.set",
        json!({
            "enabled": true, "mode": "hot-standby", "peer": format!("{peer}:8730"), "secret": PAIR_SECRET,
            "witness": ["10.99.0.1"], "interfaces": ifs, "priority": priority, "init_hold": 2
        }),
    );
}

fn active(ns: Option<u32>) -> u64 {
    call(ns, "ppp.active.list", json!({"limit": 1}))
        .ok()
        .and_then(|v| v["total"].as_u64())
        .unwrap_or(0)
}

/// Upstream bytes C counted on a sample of its sessions.
fn rx_sample(ns: Option<u32>) -> u64 {
    call(ns, "ppp.active.list", json!({"limit": 500}))
        .ok()
        .and_then(|v| {
            v["rows"]
                .as_array()
                .map(|r| r.iter().filter_map(|x| x["rx_bytes"].as_u64()).sum())
        })
        .unwrap_or(0)
}

fn monitor(ns: Option<u32>) -> Value {
    call(ns, "ppp.redundancy.monitor", json!({})).unwrap_or(Value::Null)
}

fn wait_secs(secs: u64, mut f: impl FnMut() -> bool) -> Option<f64> {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(secs) {
        if f() {
            return Some(t.elapsed().as_secs_f64());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    None
}

/// Not a test: run inside the other namespaces by `call`.
#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn bng_lab_ha() {
    if std::env::var_os("COREROUTER_BNG_LAB").is_none() {
        eprintln!("skipped: cargo xtask bng-lab --only ha");
        return;
    }
    let blaster = PathBuf::from(std::env::var("BNGBLASTER").expect("BNGBLASTER"));
    let out = PathBuf::from(std::env::var("BNG_LAB_OUT").unwrap_or_else(|_| "/tmp/bng-lab".into()));
    std::fs::create_dir_all(&out).unwrap();
    let scales: Vec<usize> = std::env::var("BNG_LAB_HA_SCALES")
        .ok()
        .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
        .unwrap_or_else(|| vec![10_000]);
    let mut md = String::from(
        "# BNG em par (G4.3h): o ativo perde a energia\n\n| Sessões | Tomada | Tráfego de volta | Sessões perdidas | Na tabela do novo | Starts (ids únicos) | Stops na tomada | Sessões com Interim do novo | Sessões sem Interim do novo |\n|---|---|---|---|---|---|---|---|---|\n",
    );
    for n in scales {
        let row = run(n, &blaster, &out);
        md.push_str(&row);
        md.push('\n');
        std::fs::write(out.join("ha-summary.md"), &md).unwrap();
    }
    eprintln!("\n{md}");
}

fn run(n: usize, blaster: &Path, out: &Path) -> String {
    let ports = n.div_ceil(PER_PORT).max(1);
    ip(None, &["link", "set", "lo", "up"]);
    let c = holder();
    let bl = holder();
    let (cp, bp) = (c.0.id(), bl.0.id());
    let (cs, bs) = (cp.to_string(), bp.to_string());
    for ns in [Some(cp), Some(bp)] {
        ip(ns, &["link", "set", "lo", "up"]);
    }
    for br in ["br0", "br1"] {
        ip(None, &["link", "add", br, "type", "bridge"]);
        ip(None, &["link", "set", br, "up"]);
    }
    let mut legs: Vec<(String, String, Option<&str>, &str)> = Vec::new();
    for i in 0..ports {
        legs.push((format!("acc{i}"), format!("acc{i}-p"), None, "br0"));
        legs.push((
            format!("acc{i}"),
            format!("accc{i}-p"),
            Some(cs.as_str()),
            "br0",
        ));
        legs.push((
            format!("cpe{i}"),
            format!("cpe{i}-p"),
            Some(bs.as_str()),
            "br0",
        ));
    }
    legs.push(("wan0".into(), "wan0-p".into(), None, "br1"));
    legs.push(("wan0".into(), "wanc-p".into(), Some(cs.as_str()), "br1"));
    legs.push(("blnet".into(), "blnet-p".into(), Some(bs.as_str()), "br1"));
    for (end, peer, ns, br) in &legs {
        match ns {
            None => ip(
                None,
                &["link", "add", end, "type", "veth", "peer", "name", peer],
            ),
            Some(pid) => ip(
                None,
                &[
                    "link", "add", peer, "type", "veth", "peer", "name", end, "netns", pid,
                ],
            ),
        }
        ip(None, &["link", "set", peer, "master", br]);
        ip(None, &["link", "set", peer, "up"]);
        let there = ns.and_then(|p| p.parse::<u32>().ok());
        ip(there, &["link", "set", end, "up"]);
    }
    for (name, a, b) in [
        ("sync0", "10.9.0.1/24", "10.9.0.2/24"),
        ("rad0", "10.8.0.1/24", "10.8.0.2/24"),
    ] {
        ip(
            None,
            &[
                "link", "add", name, "type", "veth", "peer", "name", name, "netns", &cs,
            ],
        );
        ip(None, &["link", "set", name, "up"]);
        ip(Some(cp), &["link", "set", name, "up"]);
        ip(None, &["addr", "add", a, "dev", name]);
        ip(Some(cp), &["addr", "add", b, "dev", name]);
    }
    for ns in [None, Some(cp)] {
        ip(ns, &["link", "add", "gw0", "type", "dummy"]);
        ip(ns, &["addr", "add", "10.99.0.1/24", "dev", "gw0"]);
        ip(ns, &["link", "set", "gw0", "up"]);
        sysctl(ns, "net/ipv4/ip_forward", "1");
        sysctl(ns, "net/ipv4/conf/all/rp_filter", "0");
        sysctl(ns, "net/ipv4/conf/default/rp_filter", "0");
    }
    ip(
        Some(bp),
        &["addr", "add", "198.51.100.2/24", "dev", "blnet"],
    );
    sysctl(Some(bp), "net/ipv6/conf/all/disable_ipv6", "1");
    let radius = Radius::start(n);
    let a = daemon(
        None,
        &out.join(format!("ha-{n}-a")),
        &out.join(format!("ha-{n}-a.log")),
    );
    let _cd = daemon(
        Some(cp),
        &out.join(format!("ha-{n}-c")),
        &out.join(format!("ha-{n}-c.log")),
    );
    configure(None, "198.51.100.1/24", "10.9.0.2", 200, ports, &radius);
    configure(Some(cp), "198.51.100.3/24", "10.9.0.1", 100, ports, &radius);
    wait_secs(60, || {
        monitor(None)["role"] == "active" && monitor(Some(cp))["role"] == "standby"
    })
    .expect("A active, C standby");

    let b = Blaster::start(bp, blaster, out, n);
    let setup = wait_secs(120 + n as u64 / 100, || b.counters().0 as usize >= n);
    assert!(setup.is_some(), "{n} sessions on A: {:?}", b.counters());
    wait_secs(120, || {
        let m = monitor(Some(cp));
        m["sync"]["synced"].as_u64() == Some(n as u64) && m["in_sync"] == true
    })
    .expect("C's replica complete");
    if n > SAMPLE_ALL {
        // Traffic on the sessions `rx_sample` reads (the first rows of
        // `ppp.active.list`, by name: `rad{session id}`).
        let rows = call(Some(cp), "ppp.active.list", json!({"limit": 500})).unwrap_or(Value::Null);
        let ids: Vec<u64> = rows["rows"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| r["name"].as_str()?.strip_prefix("rad")?.parse().ok())
            .collect();
        for id in &ids {
            b.cmd(json!({"command": "session-traffic-start", "arguments": {"session-id": id}}));
        }
        eprintln!("ha {n}: traffic on {} sampled sessions", ids.len());
    }
    std::thread::sleep(Duration::from_secs(10));
    let (_, flapped0) = b.counters();
    let rx0 = rx_sample(Some(cp));
    let before: Vec<(u32, String, String)> = radius.records();
    let started: std::collections::HashSet<String> = before
        .iter()
        .filter(|r| r.0 == 1)
        .map(|r| r.1.clone())
        .collect();

    // A loses power: every port down at once (the RADIUS link is the
    // server's, elsewhere in the network, and stays).
    let cut = Instant::now();
    for i in 0..ports {
        ip(None, &["link", "set", &format!("acc{i}"), "down"]);
    }
    ip(None, &["link", "set", "wan0", "down"]);
    ip(None, &["link", "set", "sync0", "down"]);
    ip(None, &["addr", "del", "10.99.0.1/24", "dev", "gw0"]);
    let takeover = wait_secs(30, || monitor(Some(cp))["role"] == "active").unwrap_or(f64::NAN);
    let back = wait_secs(60, || rx_sample(Some(cp)) > rx0)
        .map_or(f64::NAN, |_| cut.elapsed().as_secs_f64());
    // Keepalive (5 s × 3 on BNG Blaster) and interims settle.
    std::thread::sleep(Duration::from_secs(30));
    let (est, flapped1) = b.counters();
    let lost = flapped1.saturating_sub(flapped0);
    let held = active(Some(cp));
    let after = radius.records();
    let new: Vec<&(u32, String, String)> = after.iter().skip(before.len()).collect();
    let starts = after.iter().filter(|r| r.0 == 1).count();
    let unique: std::collections::HashSet<&str> =
        after.iter().filter(|r| r.0 == 1).map(|r| r.1.as_str()).collect();
    let stops = new.iter().filter(|r| r.0 == 2).count();
    let interims_c: HashMap<&str, usize> = new
        .iter()
        .filter(|r| r.0 == 3 && r.2 == "10.8.0.2")
        .fold(HashMap::new(), |mut m, r| {
            *m.entry(r.1.as_str()).or_default() += 1;
            m
        });
    let without = started
        .iter()
        .filter(|s| !interims_c.contains_key(s.as_str()))
        .count();
    let tally = |v: &[&(u32, String, String)]| {
        let mut m: std::collections::BTreeMap<(u32, String), (usize, std::collections::HashSet<String>)> =
            std::collections::BTreeMap::new();
        for r in v {
            let e = m.entry((r.0, r.2.clone())).or_default();
            e.0 += 1;
            e.1.insert(r.1.clone());
        }
        m.into_iter()
            .map(|((st, from), (c, ids))| format!("status {st} from {from}: {c} ({} sessions)", ids.len()))
            .collect::<Vec<_>>()
            .join("; ")
    };
    let before_refs: Vec<&(u32, String, String)> = before.iter().collect();
    eprintln!("ha {n}: accounting before the cut: {}", tally(&before_refs));
    eprintln!("ha {n}: accounting after the cut: {}", tally(&new));
    eprintln!(
        "ha {n}: takeover {takeover:.2} s, traffic back {back:.2} s, lost {lost}, C holds {held}, established {est}, starts {starts}, stops {stops}, C interims {}, without {without}",
        interims_c.len()
    );
    drop(b);
    drop(a);
    drop(radius);
    drop(_cd);
    drop(c);
    drop(bl);
    // Every name on this side (the other namespaces' ends go with them,
    // but asynchronously: the next scale must not find a leftover).
    let mut names: Vec<String> = ["br0", "br1", "sync0", "rad0", "gw0", "wan0", "wan0-p", "wanc-p", "blnet-p"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    for i in 0..ports {
        names.extend([format!("acc{i}"), format!("acc{i}-p"), format!("accc{i}-p"), format!("cpe{i}-p")]);
    }
    for l in &names {
        let _ = in_ns(None, "ip").args(["link", "del", l]).output();
    }
    format!(
        "| {n} | {takeover:.2} s | {back:.2} s | {lost} | {held} | {starts} ({}) | {stops} | {} | {without} |",
        unique.len(),
        interims_c.len()
    )
}

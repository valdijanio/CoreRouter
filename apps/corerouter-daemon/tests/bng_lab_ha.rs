//! G4.3h: the redundant BNG pair under BNG Blaster (`cargo xtask bng-lab
//! --only ha`). Two `--backend linux` daemons in hot standby, BNG
//! Blaster's subscribers on one access L2, a RADIUS test server both reach;
//! the active one loses power (every port down at once), and the lab
//! measures what the subscribers and the RADIUS server saw.
//!
//! ```text
//!   A (here)                     bra0 (access L2, one per port)  Bl (BNG Blaster)
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
//!   the same Acct-Session-Id after the takeover; every record with the
//!   user's own Class (binary, RFC 2865 §5.25, G4.3ha), C's included;
//! - **CoA to the old active** (G4.3hb): A's sync link and witness come
//!   back (its access and uplink stay down), A rejoins as the standby, and
//!   the RADIUS server, which still knows A, sends it a burst of CoAs
//!   (a rate each, up to 1000 sessions): A hands them to C over the sync
//!   link and answers what C did. ACKs, latency and C's rates are counted.
//!
//! With `--root` (`BNG_LAB_ROOT=1`) both nodes run the XDP data plane on
//! their ports (generic mode).
//!
//! `BNG_LAB_HA_IPOE=1` (G4.3hd): IPoE subscribers instead (DHCPv4, one
//! access port, a lease of 2 minutes so every client renews on C after
//! the takeover; RADIUS accounting only, the MAC as User-Name).
//!
//! `BNG_LAB_HA_BFD=<profile>` (G3.6h): BFD on both paths of the pair
//! (`fast`: 50 ms × 3), the access one over 10.7.0.1/.2 on `acc0`; the
//! summary adds C's timeline of the takeover (from the peer's last sign
//! of life) next to the times measured from the cut.
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

/// A namespace held by a sleeper. With root, a named one (`ip netns
/// add`): `ip netns exec` also mounts its own `/sys`, which the XDP loader
/// reads (an `nsenter --net` daemon would see this namespace's ports).
fn holder(name: &str) -> Kill {
    let root = std::env::var_os("BNG_LAB_ROOT").is_some();
    let k = if root {
        let _ = Command::new("ip").args(["netns", "del", name]).status();
        assert!(
            Command::new("ip")
                .args(["netns", "add", name])
                .status()
                .unwrap()
                .success()
        );
        Kill(
            Command::new("ip")
                .args(["netns", "exec", name, "sleep", "86400"])
                .spawn()
                .unwrap(),
        )
    } else {
        Kill(
            Command::new("unshare")
                .args(["--net", "--", "sleep", "86400"])
                .spawn()
                .unwrap(),
        )
    };
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

/// An accounting record: status, Acct-Session-Id, from, its Class
/// attributes.
type Acct = (u32, String, String, Vec<Vec<u8>>);

/// The Class user `rad{i}` gets: binary (a NUL, 0xff) and its own.
fn class_of(i: usize) -> Vec<u8> {
    let mut c = vec![0x00, 0xff];
    c.extend_from_slice(format!("plano-{i}").as_bytes());
    c
}

/// A RADIUS test server on 10.8.0.1 that keeps every accounting record.
struct Radius {
    stop: Arc<AtomicBool>,
    auth: u16,
    acct: u16,
    log: Arc<Mutex<Vec<Acct>>>,
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
            let mut reply = AttrList::new();
            corerouter_proto_radius::packet::PushAttr::push(
                &mut reply,
                corerouter_proto_radius::packet::attr::CLASS,
                &class_of(i),
            )
            .unwrap();
            srv.add_user(&format!("rad{i}"), "test", reply);
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
                        l.push((a.status, a.session_id, a.from.ip().to_string(), a.class));
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

    /// Every record so far.
    fn records(&self) -> Vec<Acct> {
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
        let ports = ports_for(n);
        let kind = if ipoe() { "ipoe" } else { "pppoe" };
        let access: Vec<Value> = (0..ports)
            .map(|i| json!({"interface": format!("cpe{i}"), "type": kind, "vlan-mode": "N:1", "session-limit": if ipoe() { n } else { PER_PORT }}))
            .collect();
        let mut cfg = json!({
            "interfaces": {
                "tx-interval": 1.0,
                "rx-interval": 1.0,
                "network": {"interface": "blnet", "address": "198.51.100.2/24", "gateway": "198.51.100.1"},
                "access": access,
            },
            "sessions": {"count": n, "max-outstanding": rate_env("BNG_LAB_HA_OUTSTANDING", 4000), "start-rate": rate_env("BNG_LAB_HA_START_RATE", 5000), "stop-rate": 10000, "reconnect": true},
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
        if ipoe() {
            // The gateway's MAC asked again every second: after the
            // takeover it is C's (only the active answers ARP).
            if let Some(o) = cfg.as_object_mut() {
                o.remove("pppoe");
                o.remove("ppp");
                o.insert(
                    "ipoe".into(),
                    json!({"ipv4": true, "ipv6": false, "arp-interval": rate_env("BNG_LAB_HA_ARP_S", 30), "arp-timeout": 1}),
                );
                o.insert(
                    "dhcp".into(),
                    json!({"enable": true, "timeout": 5, "retry": 30}),
                );
            }
        }
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

fn daemon(ns: Option<u32>, named: Option<&str>, dir: &Path, log: &Path) -> Kill {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let mut c = match named.filter(|_| std::env::var_os("BNG_LAB_ROOT").is_some()) {
        Some(n) => {
            let mut c = Command::new("ip");
            c.args(["netns", "exec", n, DAEMON]);
            c
        }
        None => in_ns(ns, DAEMON),
    };
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

/// `BNG_LAB_HA_IPOE=1`: IPoE subscribers (G4.3hd).
fn ipoe() -> bool {
    std::env::var_os("BNG_LAB_HA_IPOE").is_some()
}

/// Access ports: PPPoE spreads [`PER_PORT`] a port; IPoE takes one (its
/// subnet is the port's).
fn ports_for(n: usize) -> usize {
    if ipoe() {
        1
    } else {
        n.div_ceil(PER_PORT).max(1)
    }
}

/// A BNG Blaster rate from the environment (the lab's knobs).
fn rate_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// IPoE: the lease (T1 at half: every client renews on C in the settling).
const IPOE_LEASE: &str = "2m";

/// `BNG_LAB_HA_SINGLE=1`: node A alone, no redundancy (the A/B of what
/// the pair costs on the same machine).
fn single() -> bool {
    std::env::var_os("BNG_LAB_HA_SINGLE").is_some()
}

/// `BNG_LAB_HA_BFD`: the pair's BFD profile (G3.6h).
fn bfd_profile() -> Option<String> {
    std::env::var("BNG_LAB_HA_BFD")
        .ok()
        .filter(|v| !v.is_empty())
}

fn configure(ns: Option<u32>, uplink: &str, peer: &str, priority: u32, ports: usize, r: &Radius) {
    ok(
        ns,
        "ip.address.add",
        json!({"address": uplink, "interface": "wan0"}),
    );
    if ipoe() {
        // The same gateway on both nodes (only the active answers ARP).
        ok(
            ns,
            "ip.address.add",
            json!({"address": "100.64.0.1/14", "interface": "acc0"}),
        );
    }
    if std::env::var_os("BNG_LAB_ROOT").is_some() {
        // `--root`: the XDP data plane on both nodes (generic: veth); the
        // takeover then programs the adopted sessions into C's maps.
        for i in (0..ports)
            .map(|i| format!("acc{i}"))
            .chain(["wan0".to_owned()])
        {
            ok(
                ns,
                "ip.firewall.xdp.interface.add",
                json!({"interface": i, "mode": "generic"}),
            );
        }
    }
    ok(
        ns,
        "ip.pool.add",
        json!({"name": "clientes", "ranges": if ipoe() { "100.64.0.2-100.67.255.254" } else { "100.64.0.0/14" }}),
    );
    ok(
        ns,
        "ppp.profile.set",
        json!({"id": "default", "remote_address": "clientes"}),
    );
    ok(
        ns,
        "radius.add",
        json!({"address": "10.8.0.1", "secret": SECRET, "service": "ppp,dhcp", "authentication_port": r.auth, "accounting_port": r.acct}),
    );
    ok(
        ns,
        "ppp.aaa.set",
        json!({"use_radius": true, "accounting": true, "interim_update": 300}),
    );
    ok(
        ns,
        "radius.incoming.set",
        json!({"accept": true, "port": 3799}),
    );
    if ipoe() {
        ok(
            ns,
            "ip.dhcp-server.add",
            json!({"name": "ipoe1", "interface": "acc0", "address_pool": "clientes", "lease_time": IPOE_LEASE, "use_radius": "accounting", "ipoe": true, "conflict_detection": false}),
        );
        ok(
            ns,
            "ip.dhcp-server.network.add",
            json!({"address": "100.64.0.0/14", "gateway": "100.64.0.1", "dns_none": true}),
        );
    }
    for i in (0..ports).filter(|_| !ipoe()) {
        ok(
            ns,
            "interface.pppoe-server.server.add",
            json!({"interface": format!("acc{i}"), "authentication": "chap,pap", "padi_limit": 0, "mac_padi_limit": 0, "new_session_rate": 0, "keepalive_timeout": 30}),
        );
    }
    if single() {
        return;
    }
    let ifs: Vec<String> = (0..ports).map(|i| format!("acc{i}")).collect();
    let mut p = json!({
        "enabled": true, "mode": "hot-standby", "peer": format!("{peer}:8730"), "secret": PAIR_SECRET,
        "witness": ["10.99.0.1"], "interfaces": ifs, "priority": priority, "init_hold": 2
    });
    if let Some(prof) = bfd_profile() {
        // The access path's BFD over acc0 (A .1, C .2).
        let (me, other) = if priority == 200 {
            ("10.7.0.1", "10.7.0.2")
        } else {
            ("10.7.0.2", "10.7.0.1")
        };
        ok(
            ns,
            "ip.address.add",
            json!({"address": format!("{me}/24"), "interface": "acc0"}),
        );
        p["bfd"] = json!(prof);
        p["access_bfd"] = json!(prof);
        p["access_peer"] = json!(other);
    }
    ok(ns, "ppp.redundancy.set", p);
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

fn wait_secs(secs: u64, f: impl FnMut() -> bool) -> Option<f64> {
    wait_every(secs, Duration::from_millis(100), f)
}

/// `wait_secs` polling every `step`: 10 ms for the role (cheap; the
/// takeover with BFD is ~0.2 s), 100 ms for the table queries, which take
/// the sessions' lock and would slow the adoption they measure.
fn wait_every(secs: u64, step: Duration, mut f: impl FnMut() -> bool) -> Option<f64> {
    let t = Instant::now();
    while t.elapsed() < Duration::from_secs(secs) {
        if f() {
            return Some(t.elapsed().as_secs_f64());
        }
        std::thread::sleep(step);
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
        "# BNG em par (G4.3h): o ativo perde a energia\n\n| Sessões | Plano de dados | Tomada | Linha do tempo em C (detectado/testemunha/ativo/adotadas, do último sinal de vida) | Todas no nó novo | Tráfego de volta | Sessões perdidas | Na tabela do novo | Starts (ids únicos) | Stops na tomada | Sessões com Interim do novo | Sessões sem Interim do novo | Registros sem o Class do usuário | CoA ao nó antigo (ACK, mediana, p99, total) |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n",
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
    let ports = ports_for(n);
    ip(None, &["link", "set", "lo", "up"]);
    let c = holder("crha-c");
    let bl = holder("crha-b");
    let (cp, bp) = (c.0.id(), bl.0.id());
    let (cs, bs) = (cp.to_string(), bp.to_string());
    for ns in [Some(cp), Some(bp)] {
        ip(ns, &["link", "set", "lo", "up"]);
    }
    // One access L2 per port (an OLT or a switch each, as in an ISP): the
    // active's virtual MAC is on every port, and two ports on one L2 would
    // make the switch move it back and forth.
    let bridges: Vec<String> = (0..ports)
        .map(|i| format!("bra{i}"))
        .chain(["br1".to_owned()])
        .collect();
    for br in &bridges {
        ip(None, &["link", "add", br, "type", "bridge"]);
        ip(None, &["link", "set", br, "up"]);
    }
    let mut legs: Vec<(String, String, Option<&str>, String)> = Vec::new();
    for i in 0..ports {
        let br = format!("bra{i}");
        legs.push((format!("acc{i}"), format!("acc{i}-p"), None, br.clone()));
        legs.push((
            format!("acc{i}"),
            format!("accc{i}-p"),
            Some(cs.as_str()),
            br.clone(),
        ));
        legs.push((
            format!("cpe{i}"),
            format!("cpe{i}-p"),
            Some(bs.as_str()),
            br,
        ));
    }
    legs.push(("wan0".into(), "wan0-p".into(), None, "br1".into()));
    legs.push((
        "wan0".into(),
        "wanc-p".into(),
        Some(cs.as_str()),
        "br1".into(),
    ));
    legs.push((
        "blnet".into(),
        "blnet-p".into(),
        Some(bs.as_str()),
        "br1".into(),
    ));
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
        if ipoe() {
            // An IPoE subscriber is a neighbour entry (ARP); the default
            // table holds 1024 (`gc_thresh3`), and BNG Blaster's sessions
            // stopped there.
            for (k, v) in [
                ("gc_thresh1", n),
                ("gc_thresh2", 2 * n),
                ("gc_thresh3", 4 * n),
            ] {
                sysctl(
                    ns,
                    &format!("net/ipv4/neigh/default/{k}"),
                    &v.max(1024).to_string(),
                );
            }
        }
    }
    ip(
        Some(bp),
        &["addr", "add", "198.51.100.2/24", "dev", "blnet"],
    );
    sysctl(Some(bp), "net/ipv6/conf/all/disable_ipv6", "1");
    let radius = Radius::start(n);
    let a = daemon(
        None,
        None,
        &out.join(format!("ha-{n}-a")),
        &out.join(format!("ha-{n}-a.log")),
    );
    let _cd = daemon(
        Some(cp),
        Some("crha-c"),
        &out.join(format!("ha-{n}-c")),
        &out.join(format!("ha-{n}-c.log")),
    );
    configure(None, "198.51.100.1/24", "10.9.0.2", 200, ports, &radius);
    configure(Some(cp), "198.51.100.3/24", "10.9.0.1", 100, ports, &radius);
    if single() {
        let b = Blaster::start(bp, blaster, out, n);
        let setup = wait_secs(120 + n as u64 / 100, || b.counters().0 as usize >= n);
        std::thread::sleep(Duration::from_secs(20));
        eprintln!(
            "ha {n} single: setup {setup:?}, counters {:?}",
            b.counters()
        );
        if ipoe() {
            eprintln!(
                "ha {n} single: dhcp {}",
                call(None, "ip.dhcp-server.statistics.print", json!({})).unwrap_or(Value::Null)
            );
        }
        return format!("| {n} (nó sozinho) | — | — | — | — | — | — | — | — | — | — | — | — |");
    }
    wait_secs(60, || {
        monitor(None)["role"] == "active" && monitor(Some(cp))["role"] == "standby"
    })
    .expect("A active, C standby");

    let b = Blaster::start(bp, blaster, out, n);
    let limit = std::env::var("BNG_LAB_HA_SETUP_S")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(120 + n as u64 / 100);
    let setup = wait_secs(limit, || b.counters().0 as usize >= n);
    if setup.is_none() {
        eprintln!("A: {}", monitor(None));
        eprintln!("C: {}", monitor(Some(cp)));
    }
    assert!(setup.is_some(), "{n} sessions on A: {:?}", b.counters());
    wait_secs(120, || {
        let m = monitor(Some(cp));
        m["sync"]["synced"].as_u64() == Some(n as u64) && m["in_sync"] == true
    })
    .expect("C's replica complete");
    if n > SAMPLE_ALL && !ipoe() {
        // Traffic on the sessions `rx_sample` reads on C after the
        // takeover (the first rows of `ppp.active.list` by name, the same
        // on both nodes: `rad{session id}`), picked on A, the active now.
        let rows = call(None, "ppp.active.list", json!({"limit": 500})).unwrap_or(Value::Null);
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
    let before: Vec<Acct> = radius.records();
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
    let takeover = wait_every(30, Duration::from_millis(10), || {
        monitor(Some(cp))["role"] == "active"
    })
    .unwrap_or(f64::NAN);
    // G4.3hd: every session in C's table (adopted), from the cut.
    let adopted = wait_secs(60, || active(Some(cp)) >= n as u64)
        .map_or(f64::NAN, |_| cut.elapsed().as_secs_f64());
    let back = wait_secs(60, || rx_sample(Some(cp)) > rx0)
        .map_or(f64::NAN, |_| cut.elapsed().as_secs_f64());
    let timeline = {
        // G3.6h: C's own timeline, ms from A's last sign of life.
        let k = monitor(Some(cp))["takeovers"][0].clone();
        let ms = |key: &str| k[key].as_u64().map_or("–".to_owned(), |v| v.to_string());
        format!(
            "{}: {}/{}/{}/{} ms",
            k["detected_by"].as_str().unwrap_or("?"),
            ms("detected_ms"),
            ms("witness_ms"),
            ms("active_ms"),
            ms("adopted_ms")
        )
    };
    // Keepalive (5 s × 3 on BNG Blaster) and interims settle; IPoE: past
    // T1, every client renewed on C.
    std::thread::sleep(Duration::from_secs(if ipoe() { 75 } else { 30 }));
    let (est, flapped1) = b.counters();
    let lost = flapped1.saturating_sub(flapped0);
    let held = active(Some(cp));
    let plane = match call(Some(cp), "interface.pppoe-server.monitor", json!({}))
        .ok()
        .and_then(|m| m["dataplane"].as_bool())
    {
        Some(true) => "XDP",
        Some(false) => "caminho lento",
        None => "?",
    };
    let after = radius.records();
    let new: Vec<&Acct> = after.iter().skip(before.len()).collect();
    // G4.3ha: the Class of each session's Start, then every record of it
    // (C's Interim included) with that one, not empty and not another's.
    let class_at_start: HashMap<&str, &Vec<Vec<u8>>> = after
        .iter()
        .filter(|r| r.0 == 1)
        .map(|r| (r.1.as_str(), &r.3))
        .collect();
    let wrong_class = after
        .iter()
        .filter(|r| r.3.len() != 1 || class_at_start.get(r.1.as_str()).is_none_or(|c| **c != r.3))
        .count();
    let class_c = new
        .iter()
        .filter(|r| {
            r.2 == "10.8.0.2"
                && r.3.len() == 1
                && r.3.first().is_some_and(|c| c.starts_with(&[0x00, 0xff]))
        })
        .count();
    let starts = after.iter().filter(|r| r.0 == 1).count();
    let unique: std::collections::HashSet<&str> = after
        .iter()
        .filter(|r| r.0 == 1)
        .map(|r| r.1.as_str())
        .collect();
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
    let tally = |v: &[&Acct]| {
        let mut m: std::collections::BTreeMap<
            (u32, String),
            (usize, std::collections::HashSet<String>),
        > = std::collections::BTreeMap::new();
        for r in v {
            let e = m.entry((r.0, r.2.clone())).or_default();
            e.0 += 1;
            e.1.insert(r.1.clone());
        }
        m.into_iter()
            .map(|((st, from), (c, ids))| {
                format!("status {st} from {from}: {c} ({} sessions)", ids.len())
            })
            .collect::<Vec<_>>()
            .join("; ")
    };
    let before_refs: Vec<&Acct> = before.iter().collect();
    eprintln!("ha {n}: accounting before the cut: {}", tally(&before_refs));
    eprintln!("ha {n}: accounting after the cut: {}", tally(&new));
    eprintln!(
        "ha {n}: timeline on C {timeline}; takeover {takeover:.2} s, all on C {adopted:.2} s, traffic back {back:.2} s, lost {lost}, C holds {held}, established {est}, starts {starts}, stops {stops}, C interims {}, without {without}, wrong Class {wrong_class} (C's records with it {class_c})",
        interims_c.len()
    );
    let coa = if single() {
        "-".to_owned()
    } else {
        coa_burst(n, cp)
    };
    drop(b);
    drop(a);
    drop(radius);
    drop(_cd);
    drop(c);
    drop(bl);
    for n in ["crha-c", "crha-b"] {
        let _ = Command::new("ip").args(["netns", "del", n]).output();
    }
    // Every name on this side (the other namespaces' ends go with them,
    // but asynchronously: the next scale must not find a leftover).
    let mut names: Vec<String> = [
        "br1", "sync0", "rad0", "gw0", "wan0", "wan0-p", "wanc-p", "blnet-p",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    for i in 0..ports {
        names.push(format!("bra{i}"));
        names.extend([
            format!("acc{i}"),
            format!("acc{i}-p"),
            format!("accc{i}-p"),
            format!("cpe{i}-p"),
        ]);
    }
    for l in &names {
        let _ = in_ns(None, "ip").args(["link", "del", l]).output();
    }
    format!(
        "| {n}{}{} | {plane} | {takeover:.2} s | {timeline} | {adopted:.2} s | {back:.2} s | {lost} | {held} | {starts} ({}) | {stops} | {} | {without} | {} | {coa} |",
        if ipoe() { " IPoE" } else { "" },
        bfd_profile().map_or(String::new(), |p| format!(" BFD {p}")),
        unique.len(),
        interims_c.len(),
        // IPoE accounting only: no Access-Accept, no Class.
        if ipoe() {
            "—".to_owned()
        } else {
            wrong_class.to_string()
        },
    )
}

/// G4.3hb: A back as the standby, then a CoA per sampled session sent to
/// it (the server still knows A), after the same burst straight to C for
/// comparison; the cell for the summary.
fn coa_burst(n: usize, cp: u32) -> String {
    ip(None, &["link", "set", "sync0", "up"]);
    ip(None, &["addr", "add", "10.99.0.1/24", "dev", "gw0"]);
    let back = wait_secs(60, || monitor(None)["role"] == "standby").unwrap_or(f64::NAN);
    let _ = wait_secs(120, || monitor(None)["in_sync"] == true);
    eprintln!("ha {n}: A back as standby in {back:.2} s");
    let direct = burst(n, cp, "10.8.0.2:3799", "13M/26M");
    let via_a = burst(n, cp, "10.8.0.1:3799", "11M/22M");
    let inc = call(None, "radius.incoming.get", json!({})).unwrap_or(Value::Null);
    eprintln!(
        "ha {n}: A forwarded {} answered {}",
        inc["forwarded"], inc["forward_answered"]
    );
    format!("{via_a} (direto em C: {direct})")
}

/// A CoA (`rate`) per session of C's first 1000, sent to `to` at once:
/// "ACK/sent (applied on C), median, p99, total".
fn burst(n: usize, cp: u32, to: &str, rate: &str) -> String {
    use corerouter_proto_radius::dynauth::{RequestKind, build_request};
    use corerouter_proto_radius::packet::{AttrList, Code, Packet, PushAttr, attr};
    let rows = call(Some(cp), "ppp.active.list", json!({"limit": 1000})).unwrap_or(Value::Null);
    let ips: Vec<std::net::Ipv4Addr> = rows["rows"]
        .as_array()
        .map(|r| {
            r.iter()
                .filter_map(|x| x["address"].as_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    // 8 sockets: 256 identifiers each in flight at most.
    let socks: Vec<UdpSocket> = (0..8)
        .map(|_| {
            let s = UdpSocket::bind("10.8.0.1:0").unwrap();
            s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            s
        })
        .collect();
    let t0 = Instant::now();
    let mut sent_at: HashMap<(usize, u8), Instant> = HashMap::new();
    for (k, ip) in ips.iter().enumerate() {
        let mut l = AttrList::new();
        l.push_ipv4(attr::FRAMED_IP_ADDRESS, *ip).unwrap();
        l.push_vsa(14988, 8, rate.as_bytes()).unwrap();
        let (si, id) = (k % socks.len(), (k / socks.len()) as u8);
        let req = build_request(RequestKind::Coa, id, &l, SECRET.as_bytes(), true);
        socks[si].send_to(&req, to).unwrap();
        sent_at.insert((si, id), Instant::now());
    }
    let mut lat: Vec<f64> = Vec::new();
    let mut acks = 0;
    let mut buf = [0u8; 4096];
    let until = Instant::now() + Duration::from_secs(20);
    while lat.len() < ips.len() && Instant::now() < until {
        for (si, s) in socks.iter().enumerate() {
            while let Ok((len, _)) = s.recv_from(&mut buf) {
                let Ok(p) = Packet::parse(&buf[..len]) else {
                    continue;
                };
                if let Some(t) = sent_at.remove(&(si, p.identifier())) {
                    lat.push(t.elapsed().as_secs_f64() * 1000.0);
                    acks += usize::from(p.code() == Code::CoaAck);
                }
            }
        }
    }
    let total = t0.elapsed().as_secs_f64();
    lat.sort_by(f64::total_cmp);
    let pct = |q: f64| {
        lat.get(((lat.len() as f64 * q) as usize).min(lat.len().saturating_sub(1)))
            .copied()
            .unwrap_or(f64::NAN)
    };
    std::thread::sleep(Duration::from_secs(1));
    let applied = call(Some(cp), "ppp.active.list", json!({"limit": 1000}))
        .ok()
        .and_then(|v| {
            v["rows"]
                .as_array()
                .map(|r| r.iter().filter(|x| x["rate_limit"] == rate).count())
        })
        .unwrap_or(0);
    eprintln!(
        "ha {n}: {} CoAs to {to}: {acks} ACK, {} answered, median {:.1} ms, p99 {:.1} ms, all in {total:.2} s; C applied {applied}",
        ips.len(),
        lat.len(),
        pct(0.5),
        pct(0.99),
    );
    format!(
        "{acks}/{} ({applied} em C), {:.0} ms, {:.0} ms, {total:.2} s",
        ips.len(),
        pct(0.5),
        pct(0.99)
    )
}

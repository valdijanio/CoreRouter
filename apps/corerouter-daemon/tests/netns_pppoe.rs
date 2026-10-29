//! G4.3d: a `--backend linux` daemon's PPPoE server takes subscribers
//! from real `proto-pppoe` clients across a veth, inside a throwaway
//! network namespace, no root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_pppoe -- --test-threads 1
//! ```
//!
//! ```text
//!   daemon (BNG)                         this test (the CPEs)
//!   acc0 ───────────── veth ─────────── cpe0: N proto-pppoe clients
//!   bng0 (dummy, slow path: no XDP without root)
//!   wan0 198.51.100.1/24 (what the subscribers ping)
//! ```
//!
//! 1, 100 and n sessions reach Opened (2 000 in CI; `COREROUTER_PPPOE_E2E_SESSIONS=10000`
//! in the lab); a subscriber pings through the
//! slow path; `ppp.active.remove` ends one; a RADIUS user (the test server
//! of `proto-radius`) gets its Framed-IP and rate; every CPE reboots at
//! once and comes back. The setup rate and the daemon's memory per session
//! are printed (`docs/perf.md`).
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
use std::process::Stdio;
use std::time::{Duration, Instant};

use common::*;
use corerouter_hal_linux::pppoe_io::PppoePort;
use corerouter_model::IfName;
use corerouter_proto_pppoe::client::{Client, ClientConfig, ClientEvent, ClientOutput};
use corerouter_proto_pppoe::layers::AuthSet;
use corerouter_proto_pppoe::lcp::AuthProto;
use corerouter_proto_pppoe::wire::Mac;
use corerouter_proto_radius::packet::{AttrList, PushAttr, attr};
use corerouter_proto_radius::testserver::TestServer;
use serde_json::{Value, json};

fn daemon(dir: &std::path::Path) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join("g43d-pppoe.log")).unwrap();
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

fn batch(steps: Vec<Value>) {
    for chunk in steps.chunks(10_000) {
        let mut c = client(CONTROL, token_of(None)).unwrap();
        c.call("engine.batch", json!({"steps": chunk, "atomic": true}))
            .unwrap();
    }
}

fn active() -> usize {
    ok("ppp.active.list", json!({"limit": 1}))["total"]
        .as_u64()
        .unwrap() as usize
}

fn rss_kib(pid: u32) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap_or(0)
}

/// The CPEs: `proto-pppoe` clients on one AF_PACKET port of cpe0.
struct Cpes {
    port: PppoePort,
    clients: Vec<Client>,
    by_mac: HashMap<[u8; 6], usize>,
    up: Vec<Option<(u16, Ipv4Addr)>>,
    origin: Instant,
    out: ClientOutput,
}

impl Cpes {
    fn new(n: usize, base: usize, user: impl Fn(usize) -> (String, String), pap: bool) -> Self {
        let port = PppoePort::open(&"cpe0".parse::<IfName>().unwrap(), &[], true).unwrap();
        let mut clients = Vec::new();
        let mut by_mac = HashMap::new();
        for i in 0..n {
            let k = base + i;
            let mac = [0x02, 0x20, (k >> 16) as u8, (k >> 8) as u8, k as u8, 0x01];
            let (u, p) = user(i);
            let cfg = ClientConfig {
                mac: Mac(mac),
                ifindex: port.ifindex(),
                username: u.into_bytes(),
                password: p,
                auth: if pap {
                    AuthSet::new(&[AuthProto::Pap])
                } else {
                    AuthSet::routeros_default()
                },
                discovery_timeout_ms: 1000,
                discovery_attempts: 30,
                // CPEs that rebooted together still differ by a few hundred ms;
                // without it every retry lands in the same 8 s wave.
                discovery_jitter_pct: 25,
                keepalive_interval_ms: 0,
                ..ClientConfig::default()
            };
            let mut seed = [0x5au8; 32];
            seed[..8].copy_from_slice(&(k as u64).to_le_bytes());
            clients.push(Client::new(cfg, seed));
            by_mac.insert(mac, i);
        }
        let up = vec![None; n];
        Self {
            port,
            clients,
            by_mac,
            up,
            origin: Instant::now(),
            out: ClientOutput::new(),
        }
    }

    fn now(&self) -> u64 {
        self.origin.elapsed().as_millis() as u64
    }

    fn flush(&mut self) {
        for (_, f) in self.out.frames() {
            let _ = self.port.send(f);
        }
        let events: Vec<ClientEvent> = std::mem::take(&mut self.out.events);
        self.out.clear();
        let _ = events;
    }

    fn start_all(&mut self) {
        for i in 0..self.clients.len() {
            let now = self.now();
            self.clients[i].start(now, &mut self.out);
            self.flush();
        }
    }

    /// Run the CPEs until `done` or `secs` pass.
    fn run_until(&mut self, secs: u64, mut done: impl FnMut(&Self) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
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
                return true;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        false
    }

    fn note(&mut self, c: usize) {
        for ev in self.out.events.drain(..) {
            match ev {
                ClientEvent::Up { sid, ipv4, .. } => self.up[c] = ipv4.map(|ip| (sid, ip)),
                ClientEvent::Down { .. } => self.up[c] = None,
            }
        }
        for (_, f) in self.out.frames() {
            let _ = self.port.send(f);
        }
        self.out.clear();
    }

    fn ups(&self) -> usize {
        self.up.iter().filter(|u| u.is_some()).count()
    }
}

fn setup(users: usize) -> (Kill, std::path::PathBuf) {
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
    let dir = std::env::temp_dir().join(format!("g43d-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = daemon(&dir);
    ok(
        "ip.pool.add",
        json!({"name": "clientes", "ranges": "100.64.0.0/16"}),
    );
    ok(
        "ppp.profile.set",
        json!({"id": "default", "remote_address": "clientes", "dns_server": "1.1.1.1", "rate_limit": "10M/50M", "address_list": "online"}),
    );
    let steps: Vec<Value> = (0..users)
        .map(|i| json!({"command": "ppp.secret.add", "params": {"name": format!("u{i}"), "password": format!("p{i}")}}))
        .collect();
    batch(steps);
    (d, dir)
}

/// The only test: the namespace is shared, so the stages run in order.
#[test]
fn pppoe_server_end_to_end() {
    if !in_netns() {
        return;
    }
    // 2 000 subscribers by default: the CI runner (4 vCPUs, debug build)
    // must finish in its budget. The lab and a release run ask for 10 000+
    // with COREROUTER_PPPOE_E2E_SESSIONS; the checks are the same.
    let n: usize = std::env::var("COREROUTER_PPPOE_E2E_SESSIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n >= 200)
        .unwrap_or(2_000);
    let (daemon, _dir) = setup(n);
    let pid = daemon.0.id();
    let rss0 = rss_kib(pid);
    ok(
        "interface.pppoe-server.server.add",
        json!({
            "interface": "acc0", "padi_limit": 0, "mac_padi_limit": 0, "new_session_rate": 0, "keepalive_timeout": 60
        }),
    );
    wait_for("the pppoe service", || {
        ok("system.service.print", json!({}))
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["name"] == "pppoe" && r["state"] == "running")
    });

    // 1 session.
    let mut one = Cpes::new(1, 0, |i| (format!("u{i}"), format!("p{i}")), false);
    one.start_all();
    assert!(one.run_until(30, |c| c.ups() == 1), "one session");
    wait_for("ppp.active", || active() == 1);
    let row = ok("ppp.active.list", json!({}))["rows"][0].clone();
    assert_eq!(row["name"], "u0");
    assert_eq!(row["rate_limit"], "10M/50M");
    assert_eq!(row["encoding"], "mschap2");

    // Traffic through the slow path: ICMP echo to wan0 and back.
    let (sid, ip) = one.up[0].unwrap();
    let echo = icmp_echo(ip, Ipv4Addr::new(198, 51, 100, 1));
    let mut f = Vec::new();
    f.extend_from_slice(&row_mac(&one));
    f.extend_from_slice(&[0x02, 0x20, 0, 0, 0, 0x01]);
    f.extend_from_slice(&[0x88, 0x64, 0x11, 0x00]);
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(&((echo.len() + 2) as u16).to_be_bytes());
    f.extend_from_slice(&[0x00, 0x21]);
    f.extend_from_slice(&echo);
    let mut reply = None;
    for _ in 0..20 {
        one.port.send(&f).unwrap();
        let t = Instant::now();
        while t.elapsed() < Duration::from_millis(250) && reply.is_none() {
            one.port
                .recv(|fr| {
                    // PPPoE session, IPv4, ICMP echo reply (type 0).
                    if fr.len() > 42
                        && fr[12..14] == [0x88, 0x64]
                        && fr[20..22] == [0x00, 0x21]
                        && fr[31] == 1
                        && fr[42] == 0
                    {
                        reply = Some(fr.to_vec());
                    }
                })
                .unwrap();
            std::thread::sleep(Duration::from_millis(5));
        }
        if reply.is_some() {
            break;
        }
    }
    assert!(
        reply.is_some(),
        "the echo reply came back through bng0 and the PPPoE encapsulation"
    );
    wait_for("the counters", || {
        let r = ok("ppp.active.list", json!({}))["rows"][0].clone();
        r["rx_packets"].as_u64().unwrap_or(0) >= 1 && r["tx_packets"].as_u64().unwrap_or(0) >= 1
    });

    // The profile's address list holds the subscriber while up, and the
    // identity chip (and CGNAT › Who was?) names the login.
    let in_list = |ip: &str| {
        ok("ip.firewall.address-list.list", json!({}))
            .as_array()
            .unwrap()
            .iter()
            .any(|e| {
                e["list"] == "online" && e["address"].as_str().is_some_and(|a| a.starts_with(ip))
            })
    };
    let ip_text = ip.to_string();
    wait_for("the address list entry", || in_list(&ip_text));
    let who = ok("ip.identity.lookup", json!({"addresses": ip_text}));
    assert_eq!(who[0]["primary"]["source"], "pppoe", "{who}");
    assert_eq!(who[0]["primary"]["name"], "u0", "{who}");

    // Terminate it.
    let id = row["id"].as_str().unwrap().to_owned();
    ok("ppp.active.remove", json!({"id": id}));
    assert!(one.run_until(10, |c| c.ups() == 0), "terminated");
    wait_for("gone", || active() == 0);
    wait_for("out of the address list", || !in_list(&ip_text));
    let h = ok("ppp.history", json!({"name": "u0", "limit": 1}));
    assert_eq!(h[0]["reason"], "admin");
    drop(one);

    // 100 sessions.
    let mut hundred = Cpes::new(
        100,
        100,
        |i| (format!("u{}", 100 + i), format!("p{}", 100 + i)),
        false,
    );
    hundred.start_all();
    assert!(
        hundred.run_until(60, |c| c.ups() == 100),
        "100 sessions: {}",
        hundred.ups()
    );
    wait_for("100 active", || active() == 100);
    drop(hundred);
    // The clients vanish without PADT; drop the sessions by hand.
    ok("ppp.active.remove", json!({"server": "pppoe-acc0"}));
    wait_for("100 gone", || active() == 0);

    // n sessions, timed. The deadline grows with n (at least 20 sessions a
    // second, the slowest runner seen with the O(n) lookups, now gone).
    let rss1 = rss_kib(pid);
    let mut many = Cpes::new(n, 0, |i| (format!("u{i}"), format!("p{i}")), false);
    let t = Instant::now();
    many.start_all();
    assert!(
        many.run_until(60 + (n as u64) / 20, |c| c.ups() == n),
        "{n} sessions: {}",
        many.ups()
    );
    let secs = t.elapsed().as_secs_f64();
    wait_for("all active", || active() == n);
    let rss2 = rss_kib(pid);
    println!(
        "MEASURED pppoe e2e: {n} sessions Opened in {secs:.2} s = {:.0} sessions/s (veth, debug build, slow path); daemon RSS {rss0} → {rss1} → {rss2} KiB = {:.0} B/session",
        n as f64 / secs,
        (rss2.saturating_sub(rss1) as f64 * 1024.0) / n as f64
    );
    let st = ok("interface.pppoe-server.monitor", json!({}));
    assert_eq!(st["sessions"], n);
    let ips: std::collections::HashSet<_> = many.up.iter().flatten().map(|(_, ip)| *ip).collect();
    assert_eq!(ips.len(), n, "one address each");

    // Mass reconnect: every CPE reboots without PADT, with the protections
    // on. The rate (n/10 a second, 100..=1000) is below what a debug build
    // sets up, so the limit is what paces it: about ten seconds of new
    // sessions whatever n is.
    let rate = (n / 10).clamp(100, 1000);
    ok(
        "interface.pppoe-server.server.set",
        json!({"id": "pppoe-acc0", "new_session_rate": rate, "padi_limit": 2000, "mac_padi_limit": 1}),
    );
    let mut again = Cpes::new(n, 0, |i| (format!("u{i}"), format!("p{i}")), false);
    // The service reads the config once a second: until then the old rate
    // (none) still holds, and the BNG sets up thousands in that second.
    std::thread::sleep(Duration::from_millis(1500));
    drop(many);
    let t = Instant::now();
    again.start_all();
    assert!(
        // The rate, plus the CPEs' back-off (RFC 2516 §5: 1, 2, 4… s).
        again.run_until(120 + 6 * (n / rate) as u64, |c| c.ups() == n),
        "mass reconnect: {}",
        again.ups()
    );
    let took = t.elapsed().as_secs_f64();
    println!(
        "MEASURED pppoe e2e: mass reconnect of {n} CPEs in {took:.2} s with new_session_rate={rate}"
    );
    // One second of tokens to start, then `rate` a second.
    let floor = 0.8 * (n.saturating_sub(rate) as f64) / rate as f64;
    assert!(
        took >= floor,
        "the rate paced the reconnect: {took:.1} s < {floor:.1} s"
    );
    wait_for("all active again", || active() == n);
    let st = ok("interface.pppoe-server.monitor", json!({}));
    assert!(st["throttled"].as_u64().unwrap() > 0, "{st}");
    let replaced = ok("ppp.history", json!({"event": "down", "limit": 10000}))
        .as_array()
        .unwrap()
        .iter()
        .filter(|h| h["reason"] == "replaced")
        .count();
    // `ppp.history` returns at most 10 000 rows (the newest): above that
    // (the lab's COREROUTER_PPPOE_E2E_SESSIONS=20000), every row it shows.
    assert_eq!(
        replaced,
        n.min(10_000),
        "one-session-per-host replaced every old session"
    );
    drop(again);

    // RADIUS: the test server answers for "r…" users with a Framed-IP and
    // a rate; the secret table does not know them.
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    let acct = UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = sock.local_addr().unwrap().port();
    let acct_port = acct.local_addr().unwrap().port();
    let mut srv = TestServer::new(b"segredo", 1);
    let mut reply = AttrList::new();
    reply
        .push_ipv4(attr::FRAMED_IP_ADDRESS, Ipv4Addr::new(100, 65, 0, 9))
        .unwrap();
    srv.add_user("radius1", "senha-r", reply);
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop2 = stop.clone();
    let srv_thread = std::thread::spawn(move || {
        sock.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        acct.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let mut buf = [0u8; 4096];
        let t0 = Instant::now();
        while !stop2.load(std::sync::atomic::Ordering::Relaxed) {
            for s in [&sock, &acct] {
                let Ok((n, from)) = s.recv_from(&mut buf) else {
                    continue;
                };
                if let Some(r) = srv.handle(from, &buf[..n], t0.elapsed().as_millis() as u64) {
                    let _ = s.send_to(&r.bytes, r.to);
                }
            }
        }
    });
    ok(
        "radius.add",
        json!({"address": "127.0.0.1", "authentication_port": port, "accounting_port": acct_port, "service": "ppp", "secret": "segredo"}),
    );
    ok("ppp.aaa.set", json!({"use_radius": true}));
    std::thread::sleep(Duration::from_millis(1500));
    let mut r = Cpes::new(1, 50_000, |_| ("radius1".into(), "senha-r".into()), true);
    r.start_all();
    assert!(
        r.run_until(30, |c| c.ups() == 1),
        "RADIUS user: {} {}",
        ok("ppp.why", json!({"name": "radius1"})),
        ok("radius.monitor", json!({}))
    );
    assert_eq!(r.up[0].unwrap().1, Ipv4Addr::new(100, 65, 0, 9));
    wait_for("the RADIUS session", || {
        ok("ppp.active.list", json!({"find": "radius1"}))["rows"][0]["radius"] == true
    });
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = srv_thread.join();
    drop(daemon);
}

fn row_mac(c: &Cpes) -> [u8; 6] {
    // The BNG's MAC: acc0's.
    let _ = c;
    // /sys is the host's here: ask `ip`.
    let out = std::process::Command::new("ip")
        .args(["-o", "link", "show", "acc0"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mac = text
        .split("link/ether ")
        .nth(1)
        .and_then(|t| t.split_whitespace().next())
        .unwrap();
    let m: corerouter_model::MacAddr = mac.parse().unwrap();
    m.0
}

fn csum(b: &[u8]) -> u16 {
    let mut s: u32 = 0;
    for ch in b.chunks(2) {
        let w = u16::from_be_bytes([ch[0], *ch.get(1).unwrap_or(&0)]);
        s += u32::from(w);
    }
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

fn icmp_echo(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1];
    icmp.extend_from_slice(b"corerouter-pppoe");
    let c = csum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    let total = (20 + icmp.len()) as u16;
    let mut ip = vec![0x45, 0, 0, 0, 0, 1, 0, 0, 64, 1, 0, 0];
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let c = csum(&ip);
    ip[10..12].copy_from_slice(&c.to_be_bytes());
    ip.extend_from_slice(&icmp);
    ip
}

/// Not a test: CPEs for screenshots and manual checks of the PPP window.
/// With a daemon already serving `acc0` (its peer `cpe0` here), dial
/// `PPPOE_LAB_USERS` subscribers `u0…` (password `p<i>`), three with a
/// wrong password, and keep them up for `PPPOE_LAB_SECS`:
///
/// ```sh
/// PPPOE_LAB_USERS=40 PPPOE_LAB_SECS=600 cargo test -p corerouter-daemon \
///     --test netns_pppoe cpe_lab -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn cpe_lab() {
    let users: usize = std::env::var("PPPOE_LAB_USERS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20);
    let secs: u64 = std::env::var("PPPOE_LAB_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let mut cpes = Cpes::new(
        users + 3,
        0,
        |i| {
            if i >= users {
                (format!("u{i}"), "errada".into())
            } else {
                (format!("u{i}"), format!("p{i}"))
            }
        },
        false,
    );
    cpes.start_all();
    cpes.run_until(secs, |_| false);
}

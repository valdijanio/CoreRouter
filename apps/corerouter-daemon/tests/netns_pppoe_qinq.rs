//! G4.3l: PPPoE inside two VLAN tags (QinQ) and inside one, on the slow
//! path (no XDP without root), against a `--backend linux` daemon in a
//! throwaway network namespace, no root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_pppoe_qinq -- --test-threads 1
//! ```
//!
//! ```text
//!   daemon (BNG)                            this test (the CPEs)
//!   acc0 ── veth ── cpe0: QinQ lines, S-tag 802.1ad 100-103 × C-tag 1-100
//!   acc1 ── veth ── cpe1: one 802.1Q tag, VLANs 200-201
//!   bng0 (dummy, slow path), wan0 198.51.100.1/24
//! ```
//!
//! - 400 lines come up, one session each (`max_sessions_per_vlan=1`,
//!   TR-101 1:1): a second CPE on a line gets nothing.
//! - `ppp.active` shows both tags; RADIUS-less, so NAS-Port-Id is checked
//!   in the BNG's own tests.
//! - An ICMP echo from a QinQ subscriber to wan0 comes back inside both
//!   tags (the slow path).
//! - One tag: subscribers in VLANs 200 and 201 come up, and an untagged
//!   CPE on that port does not (before G4.3l the VLAN sockets saw nothing
//!   and the untagged one took tagged frames as untagged).
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
use std::net::Ipv4Addr;
use std::process::Stdio;
use std::time::{Duration, Instant};

use common::*;
use corerouter_hal_linux::pppoe_io::{Listen, PppoePort};
use corerouter_model::IfName;
use corerouter_proto_pppoe::client::{Client, ClientConfig, ClientEvent, ClientOutput};
use corerouter_proto_pppoe::eth::Vlans;
use corerouter_proto_pppoe::layers::AuthSet;
use corerouter_proto_pppoe::lcp::AuthProto;
use corerouter_proto_pppoe::wire::Mac;
use serde_json::{Value, json};

fn daemon(dir: &std::path::Path) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join("g43l-qinq.log")).unwrap();
    let mut c = in_ns(None, DAEMON);
    c.args([
        "--backend",
        "linux",
        "--no-discovery",
        "--manage",
        "acc*",
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
    let mut c = client(CONTROL, token_of(None)).unwrap();
    c.call("engine.batch", json!({"steps": steps, "atomic": true}))
        .unwrap();
}

fn rows() -> Vec<Value> {
    ok("ppp.active.list", json!({"limit": 5000}))["rows"]
        .as_array()
        .cloned()
        .unwrap_or_default()
}

/// CPEs on one port: client `i` is user `u<base+i>` on line `lines(i)`.
struct Cpes {
    port: PppoePort,
    clients: Vec<Client>,
    by_mac: HashMap<[u8; 6], usize>,
    up: Vec<Option<(u16, Ipv4Addr)>>,
    origin: Instant,
    out: ClientOutput,
}

impl Cpes {
    fn new(
        port: &str,
        listen: &[Listen],
        n: usize,
        base: usize,
        line: impl Fn(usize) -> Vlans,
    ) -> Self {
        let port = PppoePort::open_for(&port.parse::<IfName>().unwrap(), listen).unwrap();
        let mut clients = Vec::new();
        let mut by_mac = HashMap::new();
        for i in 0..n {
            let k = base + i;
            let mac = [0x02, 0x30, (k >> 16) as u8, (k >> 8) as u8, k as u8, 0x01];
            let cfg = ClientConfig {
                mac: Mac(mac),
                ifindex: port.ifindex(),
                vlans: line(i),
                username: format!("u{k}").into_bytes(),
                password: format!("p{k}"),
                auth: AuthSet::new(&[AuthProto::ChapMd5]),
                discovery_timeout_ms: 1000,
                discovery_attempts: 8,
                discovery_jitter_pct: 25,
                keepalive_interval_ms: 0,
                circuit_id: Some(format!("olt1 eth 1/1/1/{k}").into_bytes()),
                ..ClientConfig::default()
            };
            let mut seed = [0x6bu8; 32];
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

    fn start_all(&mut self) {
        for i in 0..self.clients.len() {
            let now = self.now();
            self.clients[i].start(now, &mut self.out);
            self.note(i);
        }
    }

    fn run_until(&mut self, secs: u64, mut done: impl FnMut(&Self) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while Instant::now() < deadline {
            let now = self.now();
            let mut frames: Vec<Vec<u8>> = Vec::new();
            self.port.recv(|f| frames.push(f.to_vec())).unwrap();
            for f in frames {
                let Some(&c) = self.by_mac.get(&f[..6]) else {
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

fn mac_of(name: &str) -> [u8; 6] {
    let out = std::process::Command::new("ip")
        .args(["-o", "link", "show", name])
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
        s += u32::from(u16::from_be_bytes([ch[0], *ch.get(1).unwrap_or(&0)]));
    }
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

fn icmp_echo(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 1];
    icmp.extend_from_slice(b"corerouter-qinq");
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

/// The QinQ line of client `i`: S-tag 100..=103, C-tag 1..=100.
fn line(i: usize) -> Vlans {
    Vlans::qinq(100 + (i / 100) as u16, 1 + (i % 100) as u16)
}

#[test]
fn qinq_and_single_tag_on_the_slow_path() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    for (a, b) in [("acc0", "cpe0"), ("acc1", "cpe1")] {
        ip(None, &["link", "add", a, "type", "veth", "peer", "name", b]);
        ip(None, &["link", "set", a, "up"]);
        ip(None, &["link", "set", b, "up"]);
    }
    ip(None, &["link", "add", "wan0", "type", "dummy"]);
    ip(None, &["addr", "add", "198.51.100.1/24", "dev", "wan0"]);
    ip(None, &["link", "set", "wan0", "up"]);
    let dir = std::env::temp_dir().join(format!("g43l-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let _d = daemon(&dir);
    ok(
        "ip.pool.add",
        json!({"name": "clientes", "ranges": "100.64.0.0/20"}),
    );
    ok(
        "ppp.profile.set",
        json!({"id": "default", "remote_address": "clientes", "dns_server": "1.1.1.1"}),
    );
    batch((0..600).map(|i| json!({"command": "ppp.secret.add", "params": {"name": format!("u{i}"), "password": format!("p{i}")}})).collect());
    ok(
        "interface.pppoe-server.server.add",
        json!({
            "interface": "acc0", "vlan_mode": "stacked", "outer_vlan_range": "100-103", "inner_vlan_range": "1-100",
            "accept_untagged": false, "max_sessions_per_vlan": 1,
            "padi_limit": 0, "mac_padi_limit": 0, "new_session_rate": 0, "keepalive_timeout": 60
        }),
    );
    ok(
        "interface.pppoe-server.server.add",
        json!({
            "interface": "acc1", "pppoe_over_vlan_range": "200-201", "accept_untagged": false,
            "padi_limit": 0, "mac_padi_limit": 0, "new_session_rate": 0, "keepalive_timeout": 60
        }),
    );
    wait_for("the pppoe service", || {
        ok("system.service.print", json!({}))
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["name"] == "pppoe" && r["state"] == "running")
    });

    // 400 QinQ lines, one CPE each, and a second CPE on line (100, 1).
    let outer: Vec<Listen> = (100..=103)
        .map(|outer| Listen::Stacked {
            outer,
            tpid: 0x88a8,
        })
        .collect();
    let mut q = Cpes::new("cpe0", &outer, 401, 0, |i| {
        if i == 400 { line(0) } else { line(i) }
    });
    let t = Instant::now();
    q.start_all();
    let all = q.run_until(120, |c| c.ups() >= 400);
    let secs = t.elapsed().as_secs_f64();
    let first_up = q.up[0].is_some();
    assert!(all, "400 QinQ lines: {}", q.ups());
    // The extra CPE stays out while the line's own is up.
    q.run_until(5, |_| false);
    assert_eq!(q.ups(), 400, "one session per line");
    assert!(
        first_up ^ q.up[400].is_some(),
        "line (100, 1) holds one of its two CPEs"
    );
    println!("MEASURED pppoe qinq e2e: 400 lines Opened in {secs:.2} s (veth, debug, slow path)");
    wait_for("400 active", || rows().len() >= 400);
    let by_name: HashMap<String, Value> = rows()
        .into_iter()
        .map(|r| (r["name"].as_str().unwrap().to_owned(), r))
        .collect();
    for i in [1usize, 199, 399] {
        let r = &by_name[&format!("u{i}")];
        let v = line(i);
        assert_eq!(
            (r["vlan"].as_u64(), r["inner_vlan"].as_u64()),
            (Some(u64::from(v.outer)), Some(u64::from(v.inner))),
            "{r}"
        );
        assert_eq!(r["circuit_id"], format!("olt1 eth 1/1/1/{i}"));
    }

    // An echo from a QinQ subscriber to wan0: back inside both tags.
    let c = 250;
    let (sid, sub_ip) = q.up[c].unwrap();
    let v = line(c);
    let echo = icmp_echo(sub_ip, Ipv4Addr::new(198, 51, 100, 1));
    let mut f = mac_of("acc0").to_vec();
    f.extend_from_slice(&q.clients[c].config().mac.0);
    f.extend_from_slice(&[0x88, 0xa8]);
    f.extend_from_slice(&v.outer.to_be_bytes());
    f.extend_from_slice(&[0x81, 0x00]);
    f.extend_from_slice(&v.inner.to_be_bytes());
    f.extend_from_slice(&[0x88, 0x64, 0x11, 0x00]);
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(&((echo.len() + 2) as u16).to_be_bytes());
    f.extend_from_slice(&[0x00, 0x21]);
    f.extend_from_slice(&echo);
    let mut reply = None;
    for _ in 0..20 {
        q.port.send(&f).unwrap();
        let t = Instant::now();
        while t.elapsed() < Duration::from_millis(250) && reply.is_none() {
            q.port
                .recv(|fr| {
                    // 802.1ad, 802.1Q, PPPoE session, IPv4, ICMP echo reply.
                    if fr.len() > 50
                        && fr[12..14] == [0x88, 0xa8]
                        && fr[16..18] == [0x81, 0x00]
                        && fr[20..22] == [0x88, 0x64]
                        && fr[28..30] == [0x00, 0x21]
                        && fr[39] == 1
                        && fr[50] == 0
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
    let reply = reply.expect("the echo reply came back through bng0, inside both tags");
    assert_eq!(&reply[14..16], &v.outer.to_be_bytes());
    assert_eq!(&reply[18..20], &v.inner.to_be_bytes());
    drop(q);

    // One tag: VLANs 200 and 201 on acc1, and an untagged CPE that must not
    // come up there.
    let single = [Listen::Vlan(200), Listen::Vlan(201), Listen::Untagged];
    let mut s = Cpes::new("cpe1", &single, 21, 500, |i| {
        if i == 20 {
            Vlans::NONE
        } else {
            Vlans::single(200 + (i % 2) as u16)
        }
    });
    s.start_all();
    assert!(
        s.run_until(60, |c| c.ups() >= 20),
        "single tag: {}",
        s.ups()
    );
    s.run_until(4, |_| false);
    assert!(
        s.up[20].is_none(),
        "the untagged CPE gets nothing on a VLAN-only server"
    );
    let r = &rows().into_iter().find(|r| r["name"] == "u501").unwrap();
    assert_eq!(
        (r["vlan"].as_u64(), r["inner_vlan"].as_u64()),
        (Some(201), None),
        "{r}"
    );
}

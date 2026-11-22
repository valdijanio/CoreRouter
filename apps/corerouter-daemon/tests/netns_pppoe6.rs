//! G4.3e: dual-stack PPPoE end to end. A `--backend linux` daemon's BNG
//! takes 10 000 `proto-pppoe` clients over a veth, inside a throwaway
//! network namespace, no root; each one opens IPCP and IPv6CP, gets the
//! session's RA (its /64 and the RDNSS) and asks for a delegated prefix
//! with a DHCPv6 Solicit (Rapid Commit), as a CPE does:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_pppoe6 -- --test-threads 1
//! ```
//!
//! ```text
//!   daemon (BNG)                         this test (the CPEs)
//!   acc0 ───────────── veth ─────────── cpe0: N dual-stack clients
//! ```
//!
//! Checked: every session has a distinct /64 and /56 (`ppp.active.list`),
//! the RA carries the /64, the DHCPv6 Reply carries the /56 and an IA_NA
//! address, the link-local of the BNG is stable across a reconnect
//! (RFC 8064), and `interface.pppoe-server.monitor` counts the bound
//! prefixes. The time to dual-stack is printed (`docs/perf.md`).
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

use std::collections::{HashMap, HashSet};
use std::net::Ipv6Addr;
use std::process::Stdio;
use std::time::{Duration, Instant};

use common::*;
use corerouter_hal_linux::pppoe_io::PppoePort;
use corerouter_model::IfName;
use corerouter_proto_dhcp::v6::{self as dhcp6, IaReq, Outgoing, msg};
use corerouter_proto_pppoe::client::{Client, ClientConfig, ClientEvent, ClientOutput};
use corerouter_proto_pppoe::layers::AuthSet;
use corerouter_proto_pppoe::lcp::AuthProto;
use corerouter_proto_pppoe::nd;
use corerouter_proto_pppoe::wire::Mac;
use serde_json::{Value, json};

fn daemon(dir: &std::path::Path) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join("g43e-pppoe6.log")).unwrap();
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

/// What a CPE learned of its IPv6.
#[derive(Default, Clone)]
struct Got {
    ra_prefix: Option<Ipv6Addr>,
    ra_dns: Vec<Ipv6Addr>,
    bng_ll: Option<Ipv6Addr>,
    pd: Option<ipnet::Ipv6Net>,
    na: Option<Ipv6Addr>,
    solicited: bool,
}

/// The CPEs: dual-stack `proto-pppoe` clients on one AF_PACKET port; the
/// IPv6 (RA, DHCPv6) is read here, the client only runs PPP.
struct Cpes {
    port: PppoePort,
    clients: Vec<Client>,
    by_mac: HashMap<[u8; 6], usize>,
    up: Vec<bool>,
    got: Vec<Got>,
    origin: Instant,
    out: ClientOutput,
    bng_mac: [u8; 6],
}

impl Cpes {
    fn new(n: usize) -> Self {
        let port = PppoePort::open(&"cpe0".parse::<IfName>().unwrap(), &[], true).unwrap();
        let mut clients = Vec::new();
        let mut by_mac = HashMap::new();
        for i in 0..n {
            let mac = [0x02, 0x30, (i >> 16) as u8, (i >> 8) as u8, i as u8, 0x01];
            let cfg = ClientConfig {
                mac: Mac(mac),
                ifindex: port.ifindex(),
                username: format!("u{i}").into_bytes(),
                password: format!("p{i}"),
                auth: AuthSet::new(&[AuthProto::ChapMd5]),
                ipv6: true,
                // Half ask the BNG for an identifier (RFC 5072 §4.1).
                ipv6_iid: (i % 2 == 0).then_some([0; 8]),
                discovery_timeout_ms: 1000,
                discovery_attempts: 30,
                keepalive_interval_ms: 0,
                ..ClientConfig::default()
            };
            let mut seed = [0x6au8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            clients.push(Client::new(cfg, seed));
            by_mac.insert(mac, i);
        }
        Self {
            port,
            clients,
            by_mac,
            up: vec![false; n],
            got: vec![Got::default(); n],
            origin: Instant::now(),
            out: ClientOutput::new(),
            bng_mac: [0; 6],
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

    fn ipv6(&mut self, c: usize, p: &[u8]) {
        if let Ok(ra) = nd::parse_ra(p) {
            self.got[c].ra_prefix = ra.prefixes.first().map(|x| x.prefix);
            self.got[c].ra_dns = ra.rdnss;
            self.got[c].bng_ll = Some(ra.src);
            return;
        }
        let Ok(h) = nd::parse_ipv6(p) else { return };
        if h.next != nd::next::UDP {
            return;
        }
        if let Some(r) = h.payload.get(8..).and_then(|b| dhcp6::decode(b).ok()) {
            self.got[c].pd = r
                .ia_pd
                .first()
                .and_then(|ia| ia.prefixes.first())
                .map(|x| x.prefix);
            self.got[c].na = r
                .ia_na
                .first()
                .and_then(|ia| ia.addrs.first())
                .map(|x| x.addr);
        }
    }

    /// The Solicit of client `c` (IA_NA + IA_PD, Rapid Commit, DNS), from
    /// its link-local to ff02::1:2, as a PPPoE session frame.
    fn solicit(&self, c: usize) -> Option<Vec<u8>> {
        let (ours, _) = self.clients[c].ipv6_iids()?;
        let duid = [
            0,
            3,
            0,
            1,
            2,
            0x30,
            (c >> 16) as u8,
            (c >> 8) as u8,
            c as u8,
            1,
        ];
        let m = Outgoing {
            kind: msg::SOLICIT,
            xid: c as u32 & 0xff_ffff,
            client_id: &duid,
            server_id: None,
            elapsed_cs: 0,
            rapid_commit: true,
            ia_na: Some(IaReq {
                iaid: 1,
                ..IaReq::default()
            }),
            ia_pd: Some(IaReq {
                iaid: 2,
                ..IaReq::default()
            }),
            oro: &[dhcp6::opt::DNS_SERVERS],
        }
        .encode();
        let mut p = Vec::new();
        nd::udp6(&mut p, nd::link_local(ours), nd::ALL_DHCP, 546, 547, &m);
        let cl = &self.clients[c];
        let mut f = Vec::new();
        f.extend_from_slice(&self.bng_mac);
        f.extend_from_slice(&cl.config().mac.0);
        f.extend_from_slice(&[0x88, 0x64, 0x11, 0x00]);
        f.extend_from_slice(&cl.session_id().to_be_bytes());
        f.extend_from_slice(&((p.len() + 2) as u16).to_be_bytes());
        f.extend_from_slice(&[0x00, 0x57]);
        f.extend_from_slice(&p);
        Some(f)
    }

    /// Run until `done` or `secs` pass; a CPE with IPv6CP up and an RA
    /// sends its Solicit (again every 2 s until a Reply).
    fn run_until(&mut self, secs: u64, mut done: impl FnMut(&Self) -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(secs);
        let mut last_solicit = vec![0u64; self.clients.len()];
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
                if self.bng_mac == [0; 6] {
                    self.bng_mac.copy_from_slice(&f[6..12]);
                }
                if f.len() > 22 && f[12..14] == [0x88, 0x64] && f[20..22] == [0x00, 0x57] {
                    self.ipv6(c, &f[22..]);
                    continue;
                }
                self.clients[c].handle_frame(now, &f, &mut self.out);
                self.note(c);
            }
            for (c, last) in last_solicit.iter_mut().enumerate() {
                if self.clients[c].next_deadline().is_some_and(|d| d <= now) {
                    self.clients[c].handle_timers(now, &mut self.out);
                    self.note(c);
                }
                let g = &self.got[c];
                if self.up[c]
                    && g.ra_prefix.is_some()
                    && g.pd.is_none()
                    && now.saturating_sub(*last) >= 2000
                    && let Some(f) = self.solicit(c)
                {
                    let _ = self.port.send(&f);
                    *last = now;
                    self.got[c].solicited = true;
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
                ClientEvent::Up { .. } => self.up[c] = true,
                ClientEvent::Down { .. } => self.up[c] = false,
            }
        }
        for (_, f) in self.out.frames() {
            let _ = self.port.send(f);
        }
        self.out.clear();
    }

    fn dual(&self) -> usize {
        (0..self.clients.len())
            .filter(|c| self.up[*c] && self.got[*c].pd.is_some())
            .count()
    }
}

fn active_rows() -> Vec<Value> {
    ok("ppp.active.list", json!({"limit": 100_000}))["rows"]
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn pppoe_dual_stack_end_to_end() {
    if !in_netns() {
        return;
    }
    let n = 10_000;
    ip(None, &["link", "set", "lo", "up"]);
    ip(
        None,
        &[
            "link", "add", "acc0", "type", "veth", "peer", "name", "cpe0",
        ],
    );
    ip(None, &["link", "set", "acc0", "up"]);
    ip(None, &["link", "set", "cpe0", "up"]);
    let dir = std::env::temp_dir().join(format!("g43e-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = daemon(&dir);
    ok(
        "ip.pool.add",
        json!({"name": "clientes", "ranges": "100.64.0.0/16"}),
    );
    ok(
        "ipv6.pool.add",
        json!({"name": "wan6", "prefix": "2001:db8:100::/48", "prefix_length": 64}),
    );
    ok(
        "ipv6.pool.add",
        json!({"name": "pd6", "prefix": "2001:db8:8000::/40", "prefix_length": 56}),
    );
    ok(
        "ppp.profile.set",
        json!({"id": "default", "remote_address": "clientes", "remote_ipv6_prefix_pool": "wan6",
               "dhcpv6_pd_pool": "pd6", "dns_server_ipv6": "2001:db8::53", "use_ipv6": "yes"}),
    );
    let steps: Vec<Value> = (0..n)
        .map(|i| json!({"command": "ppp.secret.add", "params": {"name": format!("u{i}"), "password": format!("p{i}")}}))
        .collect();
    batch(steps);
    ok(
        "interface.pppoe-server.server.add",
        json!({"interface": "acc0", "padi_limit": 0, "mac_padi_limit": 0, "new_session_rate": 0,
               "keepalive_timeout": 60, "authentication": ["chap"]}),
    );
    wait_for("the pppoe service", || {
        ok("system.service.print", json!({}))
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["name"] == "pppoe" && r["state"] == "running")
    });

    // One CPE first: the details.
    let mut one = Cpes::new(1);
    one.start_all();
    assert!(
        one.run_until(60, |c| c.dual() == 1),
        "one dual-stack session"
    );
    let g = one.got[0].clone();
    let row = active_rows()[0].clone();
    let p64: ipnet::Ipv6Net = row["ipv6_prefix"].as_str().unwrap().parse().unwrap();
    let pd: ipnet::Ipv6Net = row["delegated_prefix"].as_str().unwrap().parse().unwrap();
    assert_eq!(
        g.ra_prefix,
        Some(p64.network()),
        "the RA carries the session's /64"
    );
    assert_eq!(g.ra_dns, vec!["2001:db8::53".parse::<Ipv6Addr>().unwrap()]);
    assert_eq!(g.pd, Some(pd), "the Reply carries the session's /56");
    assert_eq!(pd.prefix_len(), 56);
    let (ours, peer) = one.clients[0].ipv6_iids().unwrap();
    assert_eq!(
        g.na,
        Some(nd::with_iid(p64.network(), ours)),
        "IA_NA = /64 + IPv6CP id"
    );
    assert_eq!(g.bng_ll, Some(nd::link_local(peer)));
    wait_for("the binding in ppp.active", || {
        active_rows()[0]["delegated_bound"] == true
    });
    // The BNG keeps its link-local for this line across a reconnect
    // (RFC 8064: stable per port, VLAN and MAC).
    let id = row["id"].as_str().unwrap().to_owned();
    ok("ppp.active.remove", json!({"id": id}));
    assert!(one.run_until(10, |c| !c.up[0]), "terminated");
    drop(one);
    wait_for("gone", || active_rows().is_empty());
    let mut again = Cpes::new(1);
    again.start_all();
    assert!(again.run_until(60, |c| c.dual() == 1), "back");
    assert_eq!(
        again.got[0].bng_ll, g.bng_ll,
        "same BNG link-local after a reconnect"
    );
    drop(again);
    ok("ppp.active.remove", json!({"server": "pppoe-acc0"}));
    wait_for("empty", || active_rows().is_empty());

    // 10 000 dual-stack sessions, timed: PADI → IPCP + IPv6CP → RA → PD.
    let mut many = Cpes::new(n);
    let t = Instant::now();
    many.start_all();
    assert!(
        many.run_until(600, |c| c.dual() == n),
        "10k dual-stack: {} of {n} ({} up)",
        many.dual(),
        many.up.iter().filter(|u| **u).count()
    );
    let secs = t.elapsed().as_secs_f64();
    println!(
        "MEASURED pppoe e2e dual-stack: {n} sessions with IPv4, /64 (RA) and /56 (DHCPv6-PD) in {secs:.2} s = {:.0} sessions/s (veth, debug build)",
        n as f64 / secs
    );
    let rows = active_rows();
    assert_eq!(rows.len(), n);
    let p64s: HashSet<&str> = rows
        .iter()
        .filter_map(|r| r["ipv6_prefix"].as_str())
        .collect();
    let pds: HashSet<&str> = rows
        .iter()
        .filter_map(|r| r["delegated_prefix"].as_str())
        .collect();
    assert_eq!((p64s.len(), pds.len()), (n, n), "one /64 and one /56 each");
    let got_pd: HashSet<_> = many.got.iter().filter_map(|g| g.pd).collect();
    assert_eq!(got_pd.len(), n, "every CPE holds its own /56");
    wait_for("the monitor", || {
        let st = ok("interface.pppoe-server.monitor", json!({}));
        st["ipv6_sessions"] == n && st["delegated"] == n
    });
    drop(many);
    ok("ppp.active.remove", json!({"server": "pppoe-acc0"}));
    wait_for("all gone", || active_rows().is_empty());
    drop(d);
}

/// Not a test: a dual-stack lab for screenshots of the PPP window. Sets up
/// the daemon as the e2e does, with its token at
/// `$PPPOE_LAB_DIR/control-7979.token` (a GUI or CLI in the same
/// namespace with `COREROUTER_RUNTIME_DIR=$PPPOE_LAB_DIR` connects), dials
/// `PPPOE_LAB_USERS` dual-stack CPEs (every third without asking for a
/// delegated prefix) and keeps them up for `PPPOE_LAB_SECS`:
///
/// ```sh
/// PPPOE_LAB_DIR=/tmp/lab6 PPPOE_LAB_USERS=30 COREROUTER_NETNS_TESTS=1 \
///   unshare --user --map-root-user --net -- \
///   cargo test -p corerouter-daemon --test netns_pppoe6 cpe_lab6 -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn cpe_lab6() {
    if !in_netns() {
        return;
    }
    let env = |k: &str, d: u64| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let users = env("PPPOE_LAB_USERS", 30) as usize;
    let secs = env("PPPOE_LAB_SECS", 900);
    let dir = std::path::PathBuf::from(
        std::env::var("PPPOE_LAB_DIR").unwrap_or_else(|_| "/tmp/lab6".into()),
    );
    ip(None, &["link", "set", "lo", "up"]);
    ip(
        None,
        &[
            "link", "add", "acc0", "type", "veth", "peer", "name", "cpe0",
        ],
    );
    ip(None, &["link", "set", "acc0", "up"]);
    ip(None, &["link", "set", "cpe0", "up"]);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let log = std::fs::File::create(dir.join("daemon.log")).unwrap();
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
    .arg("--token-file")
    .arg(dir.join("control-7979.token"))
    .stdout(Stdio::null())
    .stderr(log);
    let _d = Kill(c.spawn().unwrap());
    let _ = token_file(None, &dir);
    // `token_file` names `local.token`: point it at the real one.
    std::thread::sleep(Duration::from_millis(300));
    wait_for("the daemon", || {
        std::fs::copy(dir.join("control-7979.token"), dir.join("local.token")).is_ok()
            && call(None, "interface.list", json!({})).is_ok()
    });
    ok(
        "ip.pool.add",
        json!({"name": "clientes", "ranges": "100.64.0.0/16"}),
    );
    ok(
        "ipv6.pool.add",
        json!({"name": "wan6", "prefix": "2001:db8:100::/48", "prefix_length": 64}),
    );
    ok(
        "ipv6.pool.add",
        json!({"name": "pd6", "prefix": "2001:db8:8000::/40", "prefix_length": 56}),
    );
    ok(
        "ppp.profile.set",
        json!({"id": "default", "remote_address": "clientes", "remote_ipv6_prefix_pool": "wan6",
               "dhcpv6_pd_pool": "pd6", "dns_server_ipv6": "2001:db8::53", "rate_limit": "50M/100M"}),
    );
    ok(
        "ppp.profile.add",
        json!({"name": "so-ipv4", "use_ipv6": "no", "rate_limit": "10M/20M"}),
    );
    // Every fifth subscriber on an IPv4-only plan.
    let steps: Vec<Value> = (0..users)
        .map(|i| {
            let profile = if i % 5 == 4 { "so-ipv4" } else { "default" };
            json!({"command": "ppp.secret.add", "params": {"name": format!("u{i}"), "password": format!("p{i}"), "profile": profile}})
        })
        .collect();
    batch(steps);
    ok(
        "interface.pppoe-server.server.add",
        json!({"interface": "acc0", "padi_limit": 0, "mac_padi_limit": 0, "new_session_rate": 0,
               "keepalive_timeout": 600, "authentication": ["chap"]}),
    );
    let mut cpes = Cpes::new(users);
    // Every third CPE never asks for a prefix (it stays reserved).
    for c in (0..users).step_by(3) {
        cpes.got[c].pd = Some("::/128".parse().unwrap());
    }
    cpes.start_all();
    cpes.run_until(60, |c| c.up.iter().all(|u| *u));
    println!("LAB READY: {} up", cpes.up.iter().filter(|u| **u).count());
    cpes.run_until(secs, |_| false);
}

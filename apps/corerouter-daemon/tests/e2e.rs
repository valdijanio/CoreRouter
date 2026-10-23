//! audit-e2e: the real daemon binary end to end, on the virtual backend,
//! a temporary `--config-dir` and an ephemeral control port (no namespace,
//! no root, no discovery traffic). Each test takes a few seconds:
//!
//! - a configuration touching every area survives SIGTERM (running config
//!   and history identical), and `kill -9` in the middle of a commit storm
//!   boots the last saved revision with every acknowledged change in it;
//! - hostile lines on the control channel never crash or hang it;
//! - Safe Mode is undone when the process holding it dies;
//! - clients writing in parallel lose and duplicate nothing.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_control::Client;
use serde_json::{Value, json};

const DAEMON: &str = env!("CARGO_BIN_EXE_corerouter-daemon");

/// A daemon on its own port and config dir; killed when dropped.
struct Daemon {
    child: Child,
    port: u16,
    dir: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A fresh, empty directory for one test.
fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("cr-e2e-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl Daemon {
    fn start(dir: &Path) -> Self {
        let port = free_port();
        let child = Command::new(DAEMON)
            .args(["--control", &port.to_string(), "--no-discovery"])
            .arg("--config-dir")
            .arg(dir.join("config"))
            .arg("--token-file")
            .arg(dir.join("token"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut d = Self {
            child,
            port,
            dir: dir.to_owned(),
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        while d
            .client()
            .and_then(|mut c| c.call("ping", Value::Null))
            .is_err()
        {
            assert!(Instant::now() < deadline, "the daemon did not start");
            assert!(d.child.try_wait().unwrap().is_none(), "the daemon exited");
            thread::sleep(Duration::from_millis(50));
        }
        d
    }

    fn addr(&self) -> String {
        format!("127.0.0.1:{}", self.port)
    }

    /// A logged-in client (local token).
    fn client(&self) -> Result<Client, String> {
        let token = std::fs::read_to_string(self.dir.join("token")).map_err(|e| e.to_string())?;
        let mut c = Client::connect(&self.addr(), Duration::from_secs(2))?;
        c.set_token(Some(token.trim().to_owned()));
        // Log in now (as the CLI and MCP do): a connection that has sent
        // nothing yet holds one of the 8 logged-out slots.
        c.call("auth.whoami", Value::Null)?;
        Ok(c)
    }

    fn signal(&mut self, sig: &str) -> std::process::ExitStatus {
        Command::new("kill")
            .args([sig, &self.child.id().to_string()])
            .status()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(s) = self.child.try_wait().unwrap() {
                return s;
            }
            assert!(Instant::now() < deadline, "no exit after kill {sig}");
            thread::sleep(Duration::from_millis(20));
        }
    }
}

fn run(c: &mut Client, command: &str, params: Value) -> Result<Value, String> {
    c.call(
        "engine.execute",
        json!({"command": command, "params": params}),
    )
}

fn ok(c: &mut Client, command: &str, params: Value) -> Value {
    run(c, command, params.clone()).unwrap_or_else(|e| panic!("{command} {params}: {e}"))
}

fn inspect(c: &mut Client, path: &str) -> Value {
    c.call("state.inspect", json!({"path": path})).unwrap()
}

/// A configuration touching every area of the router.
fn build(c: &mut Client) {
    for (id, p) in [
        ("interface.bridge.add", json!({"name": "br-lan"})),
        (
            "interface.bridge.port.add",
            json!({"bridge": "br-lan", "interface": "ether2"}),
        ),
        (
            "interface.vlan.add",
            json!({"name": "vlan10", "parent": "ether1", "vlan_id": 10}),
        ),
        (
            "interface.vlan.add",
            json!({"name": "vlan20", "parent": "br-lan", "vlan_id": 20}),
        ),
        (
            "interface.bonding.add",
            json!({"name": "bond1", "slaves": ["ether3", "ether4"], "mode": "802.3ad"}),
        ),
        (
            "ip.vrf.add",
            json!({"name": "cust1", "interfaces": ["vlan20"]}),
        ),
        (
            "ip.address.add",
            json!({"address": "192.168.88.1/24", "interface": "br-lan"}),
        ),
        (
            "ip.address.add",
            json!({"address": "2001:db8::1/64", "interface": "vlan10", "comment": "q\"uote"}),
        ),
        (
            "ip.address.add",
            json!({"address": "172.16.0.1/24", "interface": "vlan20"}),
        ),
        (
            "ip.route.add",
            json!({"dst_address": "0.0.0.0/0", "gateway": "192.168.88.254"}),
        ),
        (
            "ip.route.add",
            json!({"dst_address": "172.17.0.0/16", "gateway": "172.16.0.254", "routing_table": "cust1"}),
        ),
        (
            "ip.firewall.address-list.add",
            json!({"list": "blk", "address": "203.0.113.0/24"}),
        ),
        (
            "ip.firewall.filter.add",
            json!({"chain": "input", "action": "drop", "src_address_list": "blk"}),
        ),
        (
            "ip.firewall.nat.add",
            json!({"chain": "srcnat", "action": "masquerade", "out_interface": "vlan10"}),
        ),
        (
            "ip.dns.set",
            json!({"servers": ["192.0.2.53"], "cache_size": 4096}),
        ),
        (
            "ip.dns.static.add",
            json!({"name": "router.lan", "address": "192.168.88.1"}),
        ),
        ("ip.dns.zone.add", json!({"name": "lab.test"})),
        (
            "ip.dns.zone.record.add",
            json!({"zone": "lab.test", "name": "www", "address": "192.168.88.10"}),
        ),
        (
            "ip.pool.add",
            json!({"name": "lan", "ranges": "192.168.88.100-192.168.88.200"}),
        ),
        (
            "ip.dhcp-server.add",
            json!({"name": "dhcp1", "interface": "br-lan", "address_pool": "lan"}),
        ),
        (
            "ip.dhcp-server.network.add",
            json!({"address": "192.168.88.0/24", "gateway": ["192.168.88.1"]}),
        ),
        (
            "ip.dhcp-server.lease.add",
            json!({"address": "192.168.88.50", "mac_address": "02:00:00:00:00:50"}),
        ),
        (
            "system.ntp.client.set",
            json!({"enabled": true, "servers": ["127.0.0.1"]}),
        ),
        (
            "system.logging.action.add",
            json!({"name": "rsys", "remote": "127.0.0.1", "remote_port": 9}),
        ),
        (
            "system.logging.add",
            json!({"topics": ["system"], "action": "rsys"}),
        ),
        ("system.identity.set", json!({"name": "e2e"})),
    ] {
        ok(c, id, p);
    }
}

/// Every configured item, by area, and the history: what must survive.
fn snapshot(c: &mut Client) -> (Value, Value) {
    (inspect(c, "running"), ok(c, "config.history", json!({})))
}

#[test]
fn config_and_history_survive_sigterm_and_kill_9() {
    let dir = temp_dir("restart");
    let mut d = Daemon::start(&dir);
    let mut c = d.client().unwrap();
    build(&mut c);
    // Transactional: a commit, a discarded edit and a rollback.
    ok(&mut c, "config.mode.set", json!({"mode": "transactional"}));
    ok(
        &mut c,
        "ip.address.add",
        json!({"address": "10.99.0.1/24", "interface": "ether5"}),
    );
    assert!(
        !ok(&mut c, "config.diff", json!({}))
            .as_array()
            .unwrap()
            .is_empty()
    );
    let rev = ok(&mut c, "config.commit", json!({"comment": "tx"}))["revision"]
        .as_u64()
        .unwrap();
    ok(
        &mut c,
        "ip.address.add",
        json!({"address": "10.98.0.1/24", "interface": "ether5"}),
    );
    ok(&mut c, "config.discard", json!({}));
    ok(&mut c, "config.rollback", json!({"revision": rev - 1}));
    ok(&mut c, "config.commit", json!({"comment": "undo tx"}));
    ok(&mut c, "config.mode.set", json!({"mode": "immediate"}));
    let running = inspect(&mut c, "running").to_string();
    assert!(!running.contains("10.99.0.1") && !running.contains("10.98.0.1"));
    let before = snapshot(&mut c);
    drop(c);

    assert!(d.signal("-TERM").success());
    let mut d = Daemon::start(&dir);
    let mut c = d.client().unwrap();
    assert_eq!(snapshot(&mut c), before, "SIGTERM lost config or history");

    // A commit storm cut by kill -9: every acknowledged change is there.
    let stop = Arc::new(AtomicBool::new(false));
    let storm = {
        let mut c = d.client().unwrap();
        let stop = stop.clone();
        thread::spawn(move || {
            let mut acked = Vec::new();
            for i in 0u32.. {
                if stop.load(Ordering::SeqCst) {
                    break;
                }
                let addr = format!("10.200.{}.{}", i / 250, i % 250);
                match run(
                    &mut c,
                    "ip.firewall.address-list.add",
                    json!({"list": "storm", "address": addr}),
                ) {
                    Ok(_) => acked.push(addr),
                    Err(_) => break,
                }
            }
            acked
        })
    };
    thread::sleep(Duration::from_millis(400));
    d.signal("-KILL");
    stop.store(true, Ordering::SeqCst);
    let acked = storm.join().unwrap();
    assert!(!acked.is_empty());
    let d = Daemon::start(&dir);
    let mut c = d.client().unwrap();
    let storage = c.call("state.inspect", json!({})).unwrap()["storage"].clone();
    assert!(
        storage["boot_errors"]
            .as_array()
            .is_none_or(|e| e.is_empty()),
        "{storage}"
    );
    let list = ok(&mut c, "ip.firewall.address-list.list", json!({}));
    let got: Vec<&str> = list
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["list"] == "storm")
        .filter_map(|r| r["address"].as_str())
        .collect();
    for a in &acked {
        assert!(
            got.contains(&a.as_str()),
            "acknowledged {a} lost by kill -9"
        );
    }
    // At most the one in flight is there without its reply.
    assert!(
        got.len() <= acked.len() + 1,
        "{} > {}",
        got.len(),
        acked.len()
    );
    // History numbers still only go up.
    let history = ok(&mut c, "config.history", json!({}));
    let nums: Vec<u64> = history
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["number"].as_u64().unwrap())
        .collect();
    assert!(nums.windows(2).all(|w| w[0] < w[1]), "{nums:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// One raw line on a fresh connection; what came back, `None` if closed.
fn raw(d: &Daemon, line: &[u8]) -> Option<String> {
    let mut s = TcpStream::connect(d.addr()).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(line).unwrap();
    let mut reply = String::new();
    match BufReader::new(s).read_line(&mut reply) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(reply),
    }
}

#[test]
fn hostile_lines_never_crash_or_hang_it() {
    let dir = temp_dir("hostile");
    let d = Daemon::start(&dir);
    let token = std::fs::read_to_string(dir.join("token")).unwrap();
    let token = token.trim();
    // Not JSON: the connection is dropped.
    for line in [
        &b"hello\n"[..],
        b"GET / HTTP/1.1\r\n\r\n",
        b"\xff\xfe\xfd\n",
        b"[1,2,3]\n",
    ] {
        assert_eq!(raw(&d, line), None, "{line:?}");
    }
    let deep = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
    for (line, wanted) in [
        (
            format!(
                "{{\"id\":1,\"method\":\"engine.execute\",\"token\":\"{token}\",\
                 \"params\":{{\"command\":\"ip.address.add\",\"params\":{}}}}}\n",
                deep(100_000)
            ),
            "recursion limit",
        ),
        (
            format!(
                "{{\"id\":1,\"method\":\"engine.execute\",\"token\":\"{token}\",\
                 \"params\":{{\"command\":\"ip.address.add\",\
                 \"params\":{{\"adress\":\"10.0.0.1/24\",\"interface\":\"ether1\"}}}}}}\n"
            ),
            "did you mean 'address'",
        ),
        (
            format!(
                "{{\"id\":1,\"method\":\"engine.execute\",\"token\":\"{token}\",\
                 \"params\":{{\"command\":\"system.identity.set\",\
                 \"params\":{{\"name\":\"{}\"}}}}}}\n",
                "x".repeat(1 << 20)
            ),
            "at most",
        ),
        (
            format!("{}\n", "a".repeat(17 << 20)),
            "request line exceeds 16 MiB",
        ),
    ] {
        let reply = raw(&d, line.as_bytes()).unwrap_or_default();
        assert!(reply.contains(wanted), "{wanted}: {reply}");
    }
    // 500 connections opened and closed at once.
    for _ in 0..500 {
        drop(TcpStream::connect(d.addr()).unwrap());
    }
    // The daemon reaps them on its own threads; until then the limit on
    // connections that have not logged in refuses a new one (it flaked under
    // a loaded machine). It must accept again soon, not instantly.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut c = loop {
        match d.client() {
            Ok(c) => break c,
            Err(e) if std::time::Instant::now() < deadline => {
                assert!(e.contains("have not logged in"), "{e}");
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => panic!("still refused after 10 s: {e}"),
        }
    };
    assert_eq!(c.call("ping", Value::Null).unwrap()["pong"], true);
    assert_eq!(
        ok(&mut c, "system.identity.get", json!({}))["name"],
        "CoreRouter"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn safe_mode_is_undone_when_its_holder_dies() {
    let dir = temp_dir("safe");
    let d = Daemon::start(&dir);
    let mut watcher = d.client().unwrap();
    let addr_present = |c: &mut Client| inspect(c, "running").to_string().contains("10.66.0.1/24");
    // Cancel undoes; exit keeps.
    let mut holder = d.client().unwrap();
    ok(&mut holder, "config.safe-mode.enter", json!({}));
    ok(
        &mut holder,
        "ip.address.add",
        json!({"address": "10.66.0.1/24", "interface": "ether5"}),
    );
    // Another client cannot take it nor end it without force.
    assert!(run(&mut watcher, "config.safe-mode.enter", json!({})).is_err());
    assert!(run(&mut watcher, "config.safe-mode.exit", json!({})).is_err());
    ok(&mut holder, "config.safe-mode.cancel", json!({}));
    assert!(!addr_present(&mut watcher));
    // The holder's connection dies (its process killed): undone.
    ok(&mut holder, "config.safe-mode.enter", json!({}));
    ok(
        &mut holder,
        "ip.address.add",
        json!({"address": "10.66.0.1/24", "interface": "ether5"}),
    );
    assert!(addr_present(&mut watcher));
    drop(holder);
    let deadline = Instant::now() + Duration::from_secs(5);
    while addr_present(&mut watcher) {
        assert!(Instant::now() < deadline, "Safe Mode not undone");
        thread::sleep(Duration::from_millis(50));
    }
    assert_eq!(
        watcher.call("state.inspect", json!({})).unwrap()["safe_mode"]["active"],
        false,
        "still in Safe Mode"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parallel_writers_lose_and_duplicate_nothing() {
    const CLIENTS: usize = 8;
    const OPS: usize = 12;
    let dir = temp_dir("parallel");
    let d = Daemon::start(&dir);
    // All connect first: every client is logged in before the storm.
    let clients: Vec<Client> = (0..CLIENTS).map(|_| d.client().unwrap()).collect();
    let workers: Vec<_> = clients
        .into_iter()
        .enumerate()
        .map(|(i, mut c)| {
            thread::spawn(move || {
                let mut kept = Vec::new();
                for n in 0..OPS {
                    let addr = format!("10.{i}.0.{n}");
                    let id = ok(
                        &mut c,
                        "ip.firewall.address-list.add",
                        json!({"list": format!("c{i}"), "address": addr}),
                    )["id"]
                        .clone();
                    let rule = ok(
                        &mut c,
                        "ip.firewall.filter.add",
                        json!({"chain": "forward", "comment": format!("c{i}-{n}")}),
                    )["id"]
                        .clone();
                    // Every third item is removed again.
                    if n % 3 == 0 {
                        ok(&mut c, "ip.firewall.address-list.remove", json!({"id": id}));
                        ok(&mut c, "ip.firewall.filter.remove", json!({"id": rule}));
                    } else {
                        kept.push((addr, format!("c{i}-{n}")));
                    }
                }
                kept
            })
        })
        .collect();
    let mut expected: Vec<(String, String)> = Vec::new();
    for w in workers {
        expected.extend(w.join().unwrap());
    }
    let mut c = d.client().unwrap();
    let list = ok(&mut c, "ip.firewall.address-list.list", json!({}));
    let mut got_addrs: Vec<String> = list
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["list"].as_str().is_some_and(|l| l.starts_with('c')))
        .map(|r| r["address"].as_str().unwrap().to_owned())
        .collect();
    let rules = ok(&mut c, "ip.firewall.filter.list", json!({}));
    let mut got_rules: Vec<String> = rules
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|r| r["comment"].as_str())
        .filter(|c| c.starts_with('c'))
        .map(str::to_owned)
        .collect();
    let (mut want_addrs, mut want_rules): (Vec<String>, Vec<String>) = expected.into_iter().unzip();
    for v in [
        &mut got_addrs,
        &mut got_rules,
        &mut want_addrs,
        &mut want_rules,
    ] {
        v.sort();
    }
    assert_eq!(got_addrs, want_addrs);
    assert_eq!(got_rules, want_rules);
    let history = ok(&mut c, "config.history", json!({}));
    let nums: Vec<u64> = history
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["number"].as_u64().unwrap())
        .collect();
    assert!(nums.windows(2).all(|w| w[0] < w[1]), "{nums:?}");
    // One commit per write.
    let writes = (CLIENTS * OPS * 2 + CLIENTS * OPS.div_ceil(3) * 2) as u64;
    assert!(nums.last().copied().unwrap_or(0) >= writes, "{nums:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

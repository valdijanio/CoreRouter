//! Two `corerouter-daemon`s on the two ends of a veth pair, each in its own
//! network namespace, find each other with CRDP and list each other in
//! `ip.neighbor.list` — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns
//! ```
//!
//! (`cargo xtask netns` runs it.) Router A lives in the namespace the test
//! runs in; router B in a child namespace (`unshare --net`), reached with
//! `nsenter`. Both use the virtual backend, whose first port is `ether1`, so
//! each kernel end of the veth is named `ether1` too. Control channels stay
//! on each namespace's loopback; B is queried by re-running this test binary
//! inside B (`query_helper`).
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use corerouter_control::Client;
use corerouter_engine::Session;
use corerouter_hal::VirtualHal;
use corerouter_storage_fs::FileStorage;
use serde_json::{Value, json};

const ENV: &str = "COREROUTER_NETNS_TESTS";
const QUERY_ENV: &str = "CRDP_NETNS_QUERY";
const DAEMON: &str = env!("CARGO_BIN_EXE_corerouter-daemon");
const CONTROL: &str = "127.0.0.1:7979";

/// True when the test may touch the kernel; panics outside a fresh namespace.
fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!(
            "skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net` \
             (cargo xtask netns)"
        );
        return false;
    }
    let names = link_names();
    assert_eq!(
        names,
        ["lo"],
        "{ENV}=1 but this network namespace has {names:?}, not just lo; refusing to touch it"
    );
    true
}

fn link_names() -> Vec<String> {
    let out = Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split(':').nth(1))
        .map(|n| n.trim().split('@').next().unwrap_or("").to_owned())
        .collect()
}

/// `ip …` here, or inside namespace `pid`.
fn ip(pid: Option<u32>, args: &[&str]) {
    let mut c = match pid {
        Some(pid) => {
            let mut c = Command::new("nsenter");
            c.args(["--target", &pid.to_string(), "--net", "--", "ip"]);
            c
        }
        None => Command::new("ip"),
    };
    let out = c.args(args).output().unwrap();
    assert!(
        out.status.success(),
        "ip {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Kills the process when the test ends, pass or fail.
struct Kill(Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Seconds between announcements: hold is 4 × this.
const INTERVAL: u64 = 2;

/// A config dir holding a committed config: identity, the veth's IPv4
/// address on ether1 (if any) and discovery on ether1 every `INTERVAL` s.
fn config_dir(name: &str, address: Option<&str>) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("crdp-netns-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut s = Session::with_storage(
        Box::new(VirtualHal::default()),
        Box::new(FileStorage::open(&dir).unwrap()),
    );
    s.execute("system.identity.set", &json!({ "name": name }))
        .unwrap();
    if let Some(address) = address {
        s.execute(
            "ip.address.add",
            &json!({"address": address, "interface": "ether1"}),
        )
        .unwrap();
    }
    s.execute(
        "ip.neighbor.discovery.set",
        &json!({"interfaces": ["ether1"], "interval_secs": INTERVAL}),
    )
    .unwrap();
    dir
}

fn daemon(netns: Option<u32>, dir: &Path, log: &str) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join(log)).unwrap();
    let mut c = match netns {
        Some(pid) => {
            let mut c = Command::new("nsenter");
            c.args(["--target", &pid.to_string(), "--net", "--", DAEMON]);
            c
        }
        None => Command::new(DAEMON),
    };
    c.args(["--control", "7979", "--config-dir"])
        .arg(dir)
        .env("RUST_LOG", "info,corerouter_discovery=debug")
        .stdout(Stdio::null())
        .stderr(log);
    Kill(c.spawn().unwrap())
}

fn netns_of(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/ns/net")).ok()
}

/// `ip.neighbor.list` of router A (here) or B (inside `pid`).
fn neighbors(netns: Option<u32>) -> Vec<Value> {
    let result = match netns {
        None => Client::connect(CONTROL, Duration::from_secs(1))
            .and_then(|mut c| c.call("engine.execute", json!({"command": "ip.neighbor.list"}))),
        Some(pid) => {
            let out = Command::new("nsenter")
                .args(["--target", &pid.to_string(), "--net", "--"])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "query_helper",
                    "--exact",
                    "--nocapture",
                    "--test-threads",
                    "1",
                ])
                .env(QUERY_ENV, CONTROL)
                .env_remove(ENV)
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.lines()
                .find_map(|l| l.split_once("QUERY-RESULT ").map(|(_, j)| j))
                .ok_or_else(|| format!("no result from B: {text}"))
                .and_then(|j| serde_json::from_str::<Value>(j).map_err(|e| e.to_string()))
                .and_then(|v| match v {
                    Value::Object(mut o) if o.contains_key("error") => {
                        Err(o.remove("error").map(|e| e.to_string()).unwrap_or_default())
                    }
                    other => Ok(other),
                })
        }
    };
    match result {
        Ok(Value::Array(rows)) => rows,
        other => {
            eprintln!("ip.neighbor.list in {netns:?}: {other:?}");
            Vec::new()
        }
    }
}

fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    panic!("timed out waiting for {what}");
}

fn sees<'a>(rows: &'a [Value], identity: &str) -> Option<&'a Value> {
    rows.iter().find(|r| r["identity"] == identity)
}

/// Not a test: run inside B's namespace by `neighbors(Some(pid))`.
#[test]
fn query_helper() {
    let Ok(addr) = std::env::var(QUERY_ENV) else {
        return;
    };
    let answer = Client::connect(&addr, Duration::from_secs(1))
        .and_then(|mut c| c.call("engine.execute", json!({"command": "ip.neighbor.list"})));
    let line = match answer {
        Ok(v) => v,
        Err(e) => json!({ "error": e }),
    };
    println!("QUERY-RESULT {line}");
}

#[test]
fn two_daemons_see_each_other() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    // IPv6 ff02::1 alone first, then with IPv4 broadcast as well.
    exchange(false);
    exchange(true);
}

fn exchange(v4: bool) {
    let tag = if v4 { "dual" } else { "v6" };
    // B's namespace, held open by a sleeper; the daemon joins it later.
    let holder = Kill(
        Command::new("unshare")
            .args(["--net", "--", "sleep", "300"])
            .spawn()
            .unwrap(),
    );
    let b = holder.0.id();
    let here = netns_of(std::process::id());
    wait_for("B's namespace", || {
        netns_of(b).is_some_and(|ns| Some(ns) != here)
    });

    let pid = b.to_string();
    ip(
        None,
        &[
            "link", "add", "ether1", "type", "veth", "peer", "name", "ether1", "netns", &pid,
        ],
    );
    ip(Some(b), &["link", "set", "lo", "up"]);
    if v4 {
        ip(None, &["addr", "add", "10.99.0.1/24", "dev", "ether1"]);
        ip(Some(b), &["addr", "add", "10.99.0.2/24", "dev", "ether1"]);
    }
    ip(None, &["link", "set", "ether1", "up"]);
    ip(Some(b), &["link", "set", "ether1", "up"]);

    let address = |a: &'static str| v4.then_some(a);
    let dir_a = config_dir(&format!("crdp-a-{tag}"), address("10.99.0.1/24"));
    let dir_b = config_dir(&format!("crdp-b-{tag}"), address("10.99.0.2/24"));
    let a_name = format!("crdp-a-{tag}");
    let b_name = format!("crdp-b-{tag}");
    let a = daemon(None, &dir_a, &format!("crdp-netns-a-{tag}.log"));
    let b_daemon = daemon(Some(b), &dir_b, &format!("crdp-netns-b-{tag}.log"));

    // Over IPv4 B may show up before its link-local address has passed
    // duplicate address detection; wait until it announces that too.
    let link_local = |row: &Value| {
        row["addresses"].as_array().is_some_and(|a| {
            a.iter()
                .any(|x| x.as_str().is_some_and(|x| x.starts_with("fe80::")))
        })
    };
    wait_for("A to list B with its link-local address", || {
        sees(&neighbors(None), &b_name).is_some_and(link_local)
    });
    wait_for("B to list A", || {
        sees(&neighbors(Some(b)), &a_name).is_some()
    });

    let rows = neighbors(None);
    let row = sees(&rows, &b_name).unwrap();
    assert_eq!(row["interface"], "ether1");
    assert_eq!(row["protocol"], "crdp");
    assert_eq!(row["remote_interface"], "ether1");
    assert_eq!(row["platform"], "CoreRouter");
    assert_eq!(row["mgmt"]["control"], 7979);
    let addresses: Vec<&str> = row["addresses"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        addresses.iter().any(|a| a.starts_with("fe80::")),
        "{addresses:?}"
    );
    if v4 {
        assert_eq!(row["address"], "10.99.0.2");
    }
    // One row per node and interface, though it arrives over IPv4 and IPv6.
    assert_eq!(rows.iter().filter(|r| r["identity"] == b_name).count(), 1);
    // The node id came from B's config dir.
    let saved = std::fs::read_to_string(dir_b.join("node-id")).unwrap();
    assert_eq!(row["node_id"].as_str().unwrap(), saved.trim());

    // A turns discovery off: its goodbye makes B forget it at once, well
    // before the hold time (4 × INTERVAL) would run out.
    let off = Instant::now();
    let mut c = Client::connect(CONTROL, Duration::from_secs(1)).unwrap();
    c.call(
        "engine.execute",
        json!({"command": "ip.neighbor.discovery.set", "params": {"enabled": false}}),
    )
    .unwrap();
    wait_for("B to forget A", || {
        sees(&neighbors(Some(b)), &a_name).is_none()
    });
    assert!(
        off.elapsed() < Duration::from_secs(3 * INTERVAL),
        "forgotten after {:?}: the goodbye did not arrive",
        off.elapsed()
    );
    assert!(
        neighbors(None).is_empty(),
        "A lists nothing with discovery off"
    );

    drop((a, b_daemon, holder));
    // Deleting one end of the veth deletes both.
    ip(None, &["link", "del", "ether1"]);
    for d in [dir_a, dir_b] {
        let _ = std::fs::remove_dir_all(d);
    }
}

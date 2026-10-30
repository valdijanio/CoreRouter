//! G0.31j: an ISP's firewall applied for real — 10 000 filter rules, and
//! 4 000 filter + 4 000 raw + 2 000 mangle (the T1 validation's config) —
//! on a `--backend linux` session with its config on disk, inside a
//! throwaway network namespace (no root, nothing reaches the host):
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_fw_scale -- --nocapture
//! ```
//!
//! The boot loads every rule into nftables; then the commit of one rule
//! (its comment, one matcher) is timed against a commit that touches no
//! firewall, in the session and through the daemon. The bound is loose
//! (shared CI machines): the numbers are in the output and in
//! `docs/changes/G0.31j.md`. To measure: `FW_SCALE_N=<commits>` (session
//! only) and `FW_SCALE_FILTER=<rules>` (one config of that many filter
//! rules; over ~16 000 the batch outgrows a user namespace's netlink send
//! buffer, so bigger ones run as root in the lab VM, `docs/vm-lab.md`).
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
use std::process::Command;
use std::time::{Duration, Instant};

use common::*;
use corerouter_engine::{ConfigStorage, Session};
use corerouter_firewall::sample;
use corerouter_hal_linux::LinuxHal;
use corerouter_model::firewall::{Action, FirewallRule};
use corerouter_model::{Config, ConfigStore, persist};
use corerouter_storage_fs::FileStorage;
use serde_json::json;

/// The i-th of 10.0.0.0/8's addresses.
fn host(i: u32) -> Ipv4Addr {
    Ipv4Addr::from(0x0a00_0000 | (i & 0x00ff_ffff))
}

/// One source address and one TCP port: no rule shadows another.
fn rule(id: u32, chain: &str, action: Action) -> FirewallRule {
    let src = host(id).to_string();
    let port = (1000 + id % 60_000).to_string();
    let mut r = sample::rule(
        id,
        chain,
        sample::m(&[
            ("src_address", src.as_str()),
            ("protocol", "tcp"),
            ("dst_port", port.as_str()),
        ])
        .unwrap(),
        action,
    )
    .unwrap();
    r.comment = format!("rule {id}");
    r
}

fn config(filter: u32, raw: u32, mangle: u32) -> Config {
    let mut cfg = Config::default();
    let fw = &mut cfg.ip.firewall;
    let mut id = 0;
    for i in 0..filter {
        id += 1;
        let chain = if i % 2 == 0 { "input" } else { "forward" };
        fw.filter.push(rule(id, chain, Action::Drop));
    }
    for _ in 0..raw {
        id += 1;
        fw.raw.push(rule(id, "prerouting", Action::Drop));
    }
    for _ in 0..mangle {
        id += 1;
        fw.mangle.push(rule(id, "prerouting", Action::Accept));
    }
    cfg
}

/// Rules of our table in the kernel, as `nft` lists them.
fn kernel_rules() -> usize {
    let out = Command::new("nft")
        .args(["-a", "list", "table", "inet", corerouter_firewall::TABLE])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains("# handle") && l.contains("tcp dport"))
        .count()
}

/// The kernel's unreclaimable slab (where nftables keeps the rules), KiB.
fn kernel_slab_kib() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .unwrap_or_default()
        .lines()
        .find_map(|l| l.strip_prefix("SUnreclaim:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap_or(0)
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v.get(v.len() / 2).copied().unwrap_or_default()
}

/// Boot a session on `cfg` (stored on disk first), check the kernel has
/// every rule, and time `n` commits of each kind.
fn measure(name: &str, cfg: &Config) -> (Duration, Duration, Duration) {
    let dir = std::env::temp_dir().join(format!("cr-fw-scale-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut storage = FileStorage::open(&dir).unwrap();
    storage
        .save(&persist::encode(&ConfigStore::new(cfg.clone())).unwrap())
        .unwrap();
    let slab = kernel_slab_kib();
    let t = Instant::now();
    let mut s = Session::with_storage(Box::new(LinuxHal::new()), Box::new(storage));
    let boot = t.elapsed();
    let slab = kernel_slab_kib().saturating_sub(slab);
    let fw = &s.store().running().ip.firewall;
    let total = fw.filter.len() + fw.raw.len() + fw.mangle.len();
    assert_eq!(
        total,
        (cfg.ip.firewall.filter.len() + cfg.ip.firewall.raw.len() + cfg.ip.firewall.mangle.len())
    );
    assert_eq!(
        kernel_rules(),
        total,
        "every rule in nftables after the boot"
    );
    let id = fw.filter.get(1000).unwrap().id.to_string();
    let time = |s: &mut Session, cmd: &str, p: serde_json::Value| {
        let t = Instant::now();
        s.execute(cmd, &p).unwrap_or_else(|e| panic!("{cmd}: {e}"));
        t.elapsed()
    };
    let n = std::env::var("FW_SCALE_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(9);
    let (mut iface, mut comment, mut port) = (Vec::new(), Vec::new(), Vec::new());
    for i in 0..n {
        let c = format!("c{i}");
        iface.push(time(
            &mut s,
            "system.identity.set",
            json!({"name": format!("r{i}")}),
        ));
        comment.push(time(
            &mut s,
            "ip.firewall.filter.set",
            json!({"id": id, "comment": c}),
        ));
        let p = (61_000 + i).to_string();
        port.push(time(
            &mut s,
            "ip.firewall.filter.set",
            json!({"id": id, "dst_port": p}),
        ));
    }
    assert_eq!(kernel_rules(), total, "one rule changed in place");
    let (a, b, c) = (median(iface), median(comment), median(port));
    let rss = std::fs::read_to_string("/proc/self/status")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with("VmHWM"))
        .unwrap_or_default()
        .to_owned();
    eprintln!(
        "netns_fw_scale/{name}: {rss}, kernel +{slab} KiB; {total} rules, boot {boot:?}; commit (median of {n}): \
         no firewall {a:?}, one comment {b:?}, one dst_port {c:?}"
    );
    drop(s);
    let _ = std::fs::remove_dir_all(&dir);
    (a, b, c)
}

/// The same through the real daemon (every service on, the commands over
/// the control channel), on the config `measure` left on disk.
fn measure_daemon(name: &str, cfg: &Config) -> (Duration, Duration, Duration) {
    let dir = std::env::temp_dir().join(format!("cr-fw-scaled-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut storage = FileStorage::open(&dir).unwrap();
    storage
        .save(&persist::encode(&ConfigStore::new(cfg.clone())).unwrap())
        .unwrap();
    drop(storage);
    let log = std::fs::File::create(dir.join("daemon.log")).unwrap();
    let mut c = Command::new(DAEMON);
    c.args(["--backend", "linux", "--control", "7979", "--config-dir"])
        .arg(&dir)
        .arg("--token-file")
        .arg(token_file(None, &dir))
        .env("RUST_LOG", "info")
        .stdout(std::process::Stdio::null())
        .stderr(log);
    let daemon = Kill(c.spawn().unwrap());
    wait_for("the daemon", || {
        call(None, "system.identity.get", json!({})).is_ok()
    });
    let total =
        cfg.ip.firewall.filter.len() + cfg.ip.firewall.raw.len() + cfg.ip.firewall.mangle.len();
    wait_for("the rules in nftables", || kernel_rules() == total);
    let id = cfg.ip.firewall.filter.get(1000).unwrap().id.to_string();
    let time = |cmd: &str, p: serde_json::Value| {
        let t = Instant::now();
        call(None, cmd, p).unwrap_or_else(|e| panic!("{cmd}: {e}"));
        t.elapsed()
    };
    let n = 9;
    let (mut iface, mut comment, mut port) = (Vec::new(), Vec::new(), Vec::new());
    for i in 0..n {
        iface.push(time(
            "system.identity.set",
            json!({"name": format!("r{i}")}),
        ));
        comment.push(time(
            "ip.firewall.filter.set",
            json!({"id": id, "comment": format!("c{i}")}),
        ));
        let p = (61_000 + i).to_string();
        port.push(time(
            "ip.firewall.filter.set",
            json!({"id": id, "dst_port": p}),
        ));
    }
    assert_eq!(kernel_rules(), total, "one rule changed in place");
    let (a, b, c) = (median(iface), median(comment), median(port));
    eprintln!(
        "netns_fw_scale/daemon/{name}: commit (median of {n}): \
         no firewall {a:?}, one comment {b:?}, one dst_port {c:?}"
    );
    drop(daemon);
    let _ = std::fs::remove_dir_all(&dir);
    (a, b, c)
}

#[test]
fn ten_thousand_rules_load_and_one_commits_fast() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    if !corerouter_hal_linux::nft::available() {
        eprintln!("skipped: the `nft` program (nftables) is not installed");
        return;
    }
    let mut cases = vec![
        ("4000_4000_2000".to_owned(), config(4000, 4000, 2000)),
        ("filter_10000".to_owned(), config(10_000, 0, 0)),
    ];
    if let Some(n) = std::env::var("FW_SCALE_FILTER")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        cases = vec![(format!("filter_{n}"), config(n, 0, 0))];
    }
    for (name, cfg) in cases {
        let name = name.as_str();
        let (_, comment, port) = measure(name, &cfg);
        if std::env::var_os("FW_SCALE_N").is_none() {
            let _ = measure_daemon(name, &cfg);
        }
        // Loose: tens of ms on a shared 4-vCPU runner would still pass;
        // the ~100 ms of before G0.31j would not.
        for (what, d) in [("comment", comment), ("dst_port", port)] {
            assert!(
                d < Duration::from_millis(60),
                "{name}: one {what} commit took {d:?}"
            );
        }
    }
}

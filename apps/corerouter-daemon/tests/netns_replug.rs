//! G1.3d: a port replugged between two polls on a `--backend linux`
//! daemon, inside a throwaway network namespace (no root, nothing reaches
//! the host). `ether2` is removed and made again at once, as a USB driver
//! reset does: the kernel takes its address along, and the link events put
//! it back well before the next 1 s poll would have looked (which saw the
//! same name, and before G1.3d never put it back at all).
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_replug
//! ```
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use common::*;
use serde_json::{Value, json};

fn run(command: &str, params: Value) -> Value {
    call(None, command, params).unwrap_or_else(|e| panic!("{command}: {e}"))
}

fn has_addr(dev: &str, a: &str) -> bool {
    let out = Command::new("ip")
        .args(["-o", "addr", "show", "dev", dev])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).contains(a)
}

#[test]
fn a_replugged_port_gets_its_configuration_back_at_once() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    for p in ["ether1", "ether2"] {
        ip(None, &["link", "add", p, "type", "dummy"]);
        // Up, or the boot seeds them disabled (G1.18).
        ip(None, &["link", "set", p, "up"]);
    }
    let dir = std::env::temp_dir().join(format!("g13d-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let log = std::fs::File::create(std::env::temp_dir().join("g13d-netns.log")).unwrap();
    let mut c = in_ns(None, DAEMON);
    c.args(["--backend", "linux", "--manage", "ether*"])
        .args(["--no-discovery", "--control", "7979", "--config-dir"])
        .arg(&dir)
        .arg("--token-file")
        .arg(common::token_file(None, &dir))
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(log);
    let _d = Kill(c.spawn().unwrap());
    wait_for("the daemon", || {
        call(None, "interface.list", json!({})).is_ok()
    });
    run(
        "ip.address.add",
        json!({"address": "10.73.2.1/24", "interface": "ether2"}),
    );
    wait_for("the address", || has_addr("ether2", "10.73.2.1/24"));
    // The link-events service is up once it says so.
    wait_for("the link-events service", || {
        run("system.service.print", json!({}))
            .to_string()
            .contains("listening for link changes")
    });
    // How many link changes the daemon's feed has handled, and the names of
    // the last ones (`system.service.print`).
    let handled = || -> (u64, String) {
        let text = run("system.service.print", json!({})).to_string();
        let Some((_, rest)) = text.split_once("link changes handled: ") else {
            return (0, String::new());
        };
        let n = rest
            .split(' ')
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        (n, rest.chars().take(200).collect())
    };
    let mut worst = Duration::ZERO;
    for _ in 0..3 {
        let (before, _) = handled();
        ip(None, &["link", "del", "ether2"]);
        ip(None, &["link", "add", "ether2", "type", "dummy"]);
        let at = Instant::now();
        while !has_addr("ether2", "10.73.2.1/24") {
            assert!(
                at.elapsed() < Duration::from_secs(5),
                "ether2 never got its address back"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        worst = worst.max(at.elapsed());
        // The kernel's own events reached the daemon. That a link event
        // puts the config back between two polls is the engine's test
        // (`port_absent`, a simulated clock); a wall-clock bound here could
        // not tell it from the 1 s poll on a loaded machine (940–990 ms,
        // flaked in the queue's batches).
        wait_for("the link event of ether2", || {
            let (n, last) = handled();
            n > before && last.contains("ether2")
        });
    }
    eprintln!("replug → address back: worst {worst:?}");
    // Replugged between two polls, or seen gone by one: on a loaded machine
    // the two `ip` commands drift apart and a poll may fall between them
    // (no "replugged" line, flaked in the queue's batches). Either way the
    // operator reads why the configuration was applied again.
    let log = run("log.print", json!({"find": "ether2: port"})).to_string();
    assert!(
        log.contains("ether2: port was replugged") || log.contains("ether2: port is back"),
        "{log}"
    );
}

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
    wait_for("the daemon", || call(None, "interface.list", json!({})).is_ok());
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
    let mut worst = Duration::ZERO;
    for _ in 0..3 {
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
    }
    eprintln!("replug → address back: worst {worst:?}");
    // A debug build on a busy CI runner; the poll alone would take up to
    // 1 s (and, before G1.3d, forever).
    assert!(worst < Duration::from_millis(800), "{worst:?}");
    let log = run("log.print", json!({"find": "replugged"})).to_string();
    assert!(log.contains("ether2: port was replugged"), "{log}");
}

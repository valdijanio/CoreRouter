//! G1.3e against a real kernel: a router whose saved route is refused at
//! boot (another program installed a route to the same prefix and metric
//! first, which CoreRouter never replaces) still brings its management
//! address and its firewall up, says so in the health checks and at login,
//! and installs the route once the other one is gone — no root, nothing
//! reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_boot_partial
//! ```
//!
//! (`cargo xtask netns` runs it.) Helpers outside `#[test]` fns may
//! unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::path::Path;
use std::process::{Command, Stdio};

use common::*;
use serde_json::{Value, json};

const PORT: &str = "7981";

fn ip_out(args: &[&str]) -> String {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(out.status.success(), "ip {}", args.join(" "));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn run(command: &str, params: Value) -> Result<Value, String> {
    common::client(&format!("127.0.0.1:{PORT}"), common::token_of(None)).and_then(|mut c| {
        c.call(
            "engine.execute",
            json!({"command": command, "params": params}),
        )
    })
}

fn whoami() -> Value {
    common::client(&format!("127.0.0.1:{PORT}"), common::token_of(None))
        .and_then(|mut c| c.call("auth.whoami", Value::Null))
        .unwrap()
}

/// The daemon on the linux backend.
fn daemon(dir: &Path, log: &str) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join(log)).unwrap();
    let mut c = Command::new(DAEMON);
    c.args([
        "--backend",
        "linux",
        "--no-discovery",
        "--control",
        PORT,
        "--config-dir",
    ])
    .arg(dir)
    .arg("--token-file")
    .arg(common::token_file(None, dir))
    .env("RUST_LOG", "info")
    .stdout(Stdio::null())
    .stderr(log);
    let d = Kill(c.spawn().unwrap());
    wait_for("the daemon", || run("interface.list", json!({})).is_ok());
    d
}

/// Not a test: `common::call` re-runs test binaries with it.
#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn management_comes_up_when_a_route_is_refused_at_boot() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    ip(
        None,
        &[
            "link", "add", "eth0", "type", "veth", "peer", "name", "eth1",
        ],
    );
    ip(None, &["link", "set", "eth0", "up"]);
    let dir = std::env::temp_dir().join(format!("g13e-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    // Management on eth0, a route, a firewall rule.
    let first = daemon(&dir, "g13e-netns-1.log");
    for (cmd, params) in [
        (
            "ip.address.add",
            json!({"address": "10.13.0.1/24", "interface": "eth0"}),
        ),
        (
            "ip.route.add",
            json!({"dst_address": "198.51.100.0/24", "gateway": "10.13.0.254"}),
        ),
        (
            "ip.firewall.filter.add",
            json!({"action": "drop", "chain": "forward", "comment": "g13e"}),
        ),
    ] {
        run(cmd, params).unwrap_or_else(|e| panic!("{cmd}: {e}"));
    }
    let ours = ip_out(&["route", "show", "198.51.100.0/24"]);
    assert!(ours.contains("via 10.13.0.254"), "{ours}");
    let metric = ours
        .split_whitespace()
        .skip_while(|w| *w != "metric")
        .nth(1)
        .unwrap_or("0")
        .to_owned();
    drop(first);
    // A "reboot": the kernel forgets everything, and another program
    // (a VPN on its own bridge) takes the same prefix and metric first.
    ip(None, &["addr", "flush", "dev", "eth0"]);
    ip(None, &["route", "flush", "table", "main"]);
    ip(None, &["link", "add", "docker0", "type", "bridge"]);
    ip(None, &["addr", "add", "10.30.0.1/24", "dev", "docker0"]);
    ip(None, &["link", "set", "docker0", "up"]);
    ip(
        None,
        &[
            "route",
            "add",
            "198.51.100.0/24",
            "via",
            "10.30.0.254",
            "metric",
            &metric,
        ],
    );
    assert!(!ip_out(&["-br", "addr", "show", "dev", "eth0"]).contains("10.13.0.1"));

    let second = daemon(&dir, "g13e-netns-2.log");
    assert!(
        ip_out(&["-br", "addr", "show", "dev", "eth0"]).contains("10.13.0.1/24"),
        "management address applied"
    );
    let now = ip_out(&["route", "show", "198.51.100.0/24"]);
    assert!(
        now.contains("via 10.30.0.254") && !now.contains("10.13.0.254"),
        "the other route stays, ours out: {now}"
    );
    let checks = run("system.health.check", json!({})).unwrap();
    let c = checks["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["key"] == "boot.apply")
        .cloned()
        .unwrap_or_else(|| panic!("no boot.apply check: {checks}"));
    assert_eq!(c["severity"], "error", "{c}");
    // G1.3g: only the refused route is out (`routes *N`), the rest in.
    let routes = run("ip.route.list", json!({})).unwrap();
    let refused = routes
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["dst_address"] == "198.51.100.0/24" && r["static"] == true)
        .cloned()
        .unwrap_or_else(|| panic!("our route not listed: {routes}"));
    let id = refused["id"].as_str().unwrap().to_owned();
    assert_eq!(c["value"], format!("routes {id}"), "{c}");
    assert!(
        refused["flags"].as_str().unwrap().contains('I') && refused["invalid"] == true,
        "flag I: {refused}"
    );
    assert!(
        c["reason"]
            .as_str()
            .unwrap()
            .contains("refusing to replace"),
        "{c}"
    );
    assert_eq!(whoami()["boot_errors"][0]["section"], "routes");
    assert_eq!(whoami()["boot_errors"][0]["item"], id.as_str());
    // The firewall, after the routes, went in.
    let nft = Command::new("nft")
        .args(["list", "table", "inet", "corerouter"])
        .output();
    if let Ok(out) = nft
        && out.status.success()
    {
        let t = String::from_utf8_lossy(&out.stdout);
        assert!(
            t.contains("chain filter_forward") && t.contains("drop"),
            "firewall applied: {t}"
        );
    }
    // A commit elsewhere still works.
    run(
        "ip.address.add",
        json!({"address": "10.14.0.1/24", "interface": "eth0"}),
    )
    .unwrap();
    assert!(ip_out(&["-br", "addr", "show", "dev", "eth0"]).contains("10.14.0.1/24"));
    // The other route goes away: ours goes in on a retry.
    ip(
        None,
        &[
            "route",
            "del",
            "198.51.100.0/24",
            "via",
            "10.30.0.254",
            "metric",
            &metric,
        ],
    );
    wait_for("the route on a retry", || {
        ip_out(&["route", "show", "198.51.100.0/24"]).contains("via 10.13.0.254")
    });
    wait_for("the boot error to clear", || {
        whoami().get("boot_errors").is_none()
    });

    drop(second);
    ip(None, &["link", "del", "eth0"]);
    ip(None, &["link", "del", "docker0"]);
    let _ = std::fs::remove_dir_all(&dir);
}

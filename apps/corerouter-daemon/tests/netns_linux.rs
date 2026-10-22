//! G1.18: `corerouter-daemon --backend linux` inside a throwaway network
//! namespace sees exactly that namespace's links (not the host's, which
//! sysfs would show), configures the ones it manages, and leaves a bridge
//! someone else made alone — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_linux
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

use std::process::{Command, Stdio};

use common::*;
use serde_json::{Value, json};

const PORT: &str = "7996";

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

fn list() -> Vec<Value> {
    match run("interface.list", json!({})).unwrap() {
        Value::Array(rows) => rows,
        other => panic!("{other}"),
    }
}

fn row<'a>(rows: &'a [Value], name: &str) -> &'a Value {
    rows.iter()
        .find(|r| r["name"] == name)
        .unwrap_or_else(|| panic!("{name} not listed: {rows:?}"))
}

fn names(rows: &[Value]) -> Vec<&str> {
    let mut out: Vec<&str> = rows.iter().map(|r| r["name"].as_str().unwrap()).collect();
    out.sort_unstable();
    out
}

/// Not a test: `common::call` re-runs test binaries with it.
#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn linux_backend_sees_its_namespace_and_owns_only_its_links() {
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
    let dir = std::env::temp_dir().join(format!("g118-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let log = std::fs::File::create(std::env::temp_dir().join("g118-netns.log")).unwrap();
    let mut c = Command::new(DAEMON);
    c.args([
        "--backend",
        "linux",
        "--no-discovery",
        "--control",
        PORT,
        "--config-dir",
    ])
    .arg(&dir)
    .arg("--token-file")
    .arg(common::token_file(None, &dir))
    .env("RUST_LOG", "info")
    .stdout(Stdio::null())
    .stderr(log);
    let daemon = Kill(c.spawn().unwrap());
    wait_for("the daemon", || run("interface.list", json!({})).is_ok());

    // Exactly this namespace's links, with the kernel's kinds.
    let rows = list();
    assert_eq!(names(&rows), ["eth0", "eth1", "lo"], "{rows:?}");
    for (name, kind, managed) in [
        ("eth0", "veth", true),
        ("eth1", "veth", true),
        ("lo", "loopback", false),
    ] {
        let r = row(&rows, name);
        assert_eq!(r["kind"], kind, "{r}");
        assert_eq!(r["managed"], managed, "{r}");
    }
    // The seed took the admin state from the kernel: eth1 stays down.
    assert_eq!(row(&rows, "eth1")["disabled"], true);
    assert!(!ip_out(&["-o", "link", "show", "eth1"]).contains(",UP"));

    // A managed veth takes an address, in this namespace's kernel.
    run(
        "ip.address.add",
        json!({"address": "10.9.0.1/24", "interface": "eth0"}),
    )
    .unwrap();
    assert!(ip_out(&["-br", "addr", "show", "dev", "eth0"]).contains("10.9.0.1/24"));

    // A bridge made by someone else (Docker, say) shows up as unmanaged and
    // refuses changes; the kernel keeps it as it was.
    ip(None, &["link", "add", "docker0", "type", "bridge"]);
    ip(None, &["link", "set", "docker0", "mtu", "1400"]);
    let rows = list();
    let d = row(&rows, "docker0");
    assert_eq!(d["managed"], false, "{d}");
    assert_eq!(d["kind"], "bridge");
    assert!(
        d["unmanaged_reason"]
            .as_str()
            .is_some_and(|w| w.contains("outside CoreRouter")),
        "{d}"
    );
    for (cmd, params) in [
        ("interface.set", json!({"name": "docker0", "mtu": 1500})),
        ("interface.bridge.add", json!({"name": "docker0"})),
        (
            "ip.address.add",
            json!({"address": "10.8.0.1/24", "interface": "docker0"}),
        ),
        (
            "interface.bridge.port.add",
            json!({"bridge": "docker0", "interface": "eth1"}),
        ),
    ] {
        let err = run(cmd, params).unwrap_err();
        assert!(err.contains("not managed by CoreRouter"), "{cmd}: {err}");
    }
    // A later apply (MTU of eth0) leaves docker0 as it was.
    run("interface.set", json!({"name": "eth0", "mtu": 1400})).unwrap();
    assert!(ip_out(&["-o", "link", "show", "eth0"]).contains("mtu 1400"));
    let dock = ip_out(&["-o", "link", "show", "docker0"]);
    assert!(dock.contains("mtu 1400") && !dock.contains(",UP"), "{dock}");
    assert!(!ip_out(&["-o", "link", "show", "eth0"]).contains("master"));

    drop(daemon);
    ip(None, &["link", "del", "eth0"]);
    ip(None, &["link", "del", "docker0"]);
    let _ = std::fs::remove_dir_all(&dir);
}

//! G0.27: a daemon stopped with SIGTERM writes the config checkpoint, so
//! the commits its config journal held are in the slot: a restart replays
//! nothing, and a build from before the journal (G0.22) that boots the same
//! directory, reading only the slots and revision files, loses none.
//!
//! A virtual lab with `--config-dir` in a temporary directory: no root, no
//! namespace.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(unix)]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_control::Client;
use corerouter_engine::Session;
use corerouter_hal::VirtualHal;
use corerouter_storage_fs::FileStorage;
use serde_json::{Value, json};

const DAEMON: &str = env!("CARGO_BIN_EXE_corerouter-daemon");

struct Daemon {
    child: Child,
    control: String,
    token_file: std::path::PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn call(d: &Daemon, command: &str, params: Value) -> Result<Value, String> {
    let token = std::fs::read_to_string(&d.token_file).map_err(|e| e.to_string())?;
    Client::connect(&d.control, Duration::from_millis(500)).and_then(|mut c| {
        c.set_token(Some(token.trim().to_owned()));
        c.call(
            "engine.execute",
            json!({"command": command, "params": params}),
        )
    })
}

fn start(dir: &std::path::Path) -> Daemon {
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let token_file = dir.with_extension(format!("{port}.token"));
    let child = Command::new(DAEMON)
        .args(["--control", &port.to_string()])
        .arg("--config-dir")
        .arg(dir)
        .arg("--token-file")
        .arg(&token_file)
        .env("RUST_LOG", "info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let d = Daemon {
        child,
        control: format!("127.0.0.1:{port}"),
        token_file,
    };
    let deadline = Instant::now() + Duration::from_secs(20);
    while call(&d, "system.identity.set", json!({"name": "ckpt"})).is_err() {
        assert!(Instant::now() < deadline, "the control port never answered");
        thread::sleep(Duration::from_millis(50));
    }
    d
}

/// What `dir` boots as: the whole directory, or only what a build from
/// before the journal reads (the journal moved away).
fn boot(dir: &std::path::Path, journal: bool) -> Session {
    let copy = dir.with_extension(if journal { "with" } else { "without" });
    let _ = std::fs::remove_dir_all(&copy);
    std::fs::create_dir_all(&copy).unwrap();
    for e in std::fs::read_dir(dir).unwrap() {
        let e = e.unwrap();
        let name = e.file_name();
        if !journal && name.to_string_lossy().starts_with("journal-") {
            continue;
        }
        if e.file_type().unwrap().is_file() {
            std::fs::copy(e.path(), copy.join(&name)).unwrap();
        }
    }
    Session::with_storage(
        Box::new(VirtualHal::default()),
        Box::new(FileStorage::open(&copy).unwrap()),
    )
}

#[test]
fn sigterm_puts_the_journaled_commits_in_the_slot() {
    let dir = std::env::temp_dir().join(format!("cr-g027-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut d = start(&dir);
    for i in 0..20 {
        call(
            &d,
            "ip.firewall.address-list.add",
            json!({"list": "l", "address": format!("10.0.0.{i}")}),
        )
        .unwrap();
    }
    let journal = std::fs::read_to_string(dir.join("journal-config.log")).unwrap_or_default();
    assert!(
        journal.lines().count() > 0,
        "the commits went to the journal"
    );
    // Before the stop, the slot alone is behind.
    assert!(
        boot(&dir, false)
            .store()
            .running()
            .ip
            .firewall
            .address_lists
            .len()
            < 20
    );

    let status = Command::new("kill")
        .args(["-TERM", &d.child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let deadline = Instant::now() + Duration::from_secs(20);
    let code = loop {
        if let Some(s) = d.child.try_wait().unwrap() {
            break s;
        }
        assert!(Instant::now() < deadline, "the daemon did not stop");
        thread::sleep(Duration::from_millis(50));
    };
    assert!(code.success(), "{code:?}");

    let restarted = boot(&dir, true);
    let old_build = boot(&dir, false);
    for s in [&restarted, &old_build] {
        assert!(
            s.storage_status().boot_errors.is_empty(),
            "{:?}",
            s.storage_status()
        );
        assert_eq!(s.store().running().ip.firewall.address_lists.len(), 20);
        assert_eq!(s.store().running().system.identity, "ckpt");
    }
    assert_eq!(
        restarted.store().current_revision(),
        old_build.store().current_revision()
    );
    for suffix in ["with", "without"] {
        let _ = std::fs::remove_dir_all(dir.with_extension(suffix));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// fix-journal-routing-delta: a daemon killed with SIGKILL (power cut, OOM
/// kill) comes back with its OSPF, MPLS/LDP, BFD and RPKI config. Those
/// commits reached the journal as `{}` and the restart replayed nothing.
#[test]
fn sigkill_keeps_the_routing_config() {
    let dir = std::env::temp_dir().join(format!("cr-routing-kill-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut d = start(&dir);
    let steps = [
        (
            "ip.address.add",
            json!({"address": "192.0.2.1/24", "interface": "ether1"}),
        ),
        (
            "routing.bfd.profile.add",
            json!({"name": "core", "min_tx": 100, "min_rx": 100}),
        ),
        (
            "routing.ospf.instance.add",
            json!({"name": "v2", "router_id": "10.255.0.1"}),
        ),
        (
            "routing.ospf.area.add",
            json!({"name": "bb", "instance": "v2", "area_id": "0.0.0.0"}),
        ),
        (
            "routing.ospf.interface-template.add",
            json!({"area": "bb", "interfaces": "ether1", "cost": 10}),
        ),
        ("mpls.ldp.add", json!({"lsr_id": "10.255.0.1"})),
        ("mpls.ldp.interface.add", json!({"interface": "ether1"})),
        (
            "routing.rpki.add",
            json!({"name": "rtr", "address": "192.0.2.3"}),
        ),
    ];
    for (id, params) in &steps {
        call(&d, id, params.clone()).unwrap_or_else(|e| panic!("{id}: {e}"));
    }
    let lists = [
        "routing.bfd.profile.list",
        "routing.ospf.instance.list",
        "routing.ospf.area.list",
        "routing.ospf.interface-template.list",
        "mpls.ldp.list",
        "mpls.ldp.interface.list",
        "routing.rpki.list",
    ];
    // Only the configured part: a list may carry live state too.
    let config = |d: &Daemon| -> Value {
        Value::Array(
            lists
                .iter()
                .map(|l| call(d, l, json!({})).unwrap_or_else(|e| panic!("{l}: {e}")))
                .collect(),
        )
    };
    let before = config(&d);
    d.child.kill().unwrap();
    d.child.wait().unwrap();
    let d = start(&dir);
    let after = config(&d);
    for (i, l) in lists.iter().enumerate() {
        assert_eq!(after[i], before[i], "{l} after SIGKILL");
    }
    assert!(
        before[1].to_string().contains("10.255.0.1"),
        "{}",
        before[1]
    );
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

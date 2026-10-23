//! Control audit (finding 1): the owner of Safe Mode cuts its own management path (its
//! address goes away: no FIN, no RST ever arrives) and the router must
//! still notice and undo the change. Before TCP keepalive the server
//! thread waited in `read` forever and the operator stayed locked out.
//! Also: a network peer that has not logged in gets only short lines and
//! no build details.
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-control --test netns_safe_mode_drop
//! ```
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::TcpListener;
use std::process::Command;
use std::time::{Duration, Instant};

use corerouter_control::{Client, Endpoint, Gate, SharedHost, Timeouts, spawn};
use corerouter_engine::{Session, Shared, shared};
use serde_json::{Value, json};

const ADDR: &str = "10.77.0.1";
const PW: &str = "admin-password";

fn ip(args: &[&str]) {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "ip {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn ether2_disabled(session: &Shared) -> bool {
    corerouter_engine::lock(session)
        .store()
        .running()
        .interfaces
        .values()
        .any(|i| i.name.as_str() == "ether2" && i.disabled)
}

#[test]
fn safe_mode_is_undone_when_the_owners_path_dies_silently() {
    if std::env::var_os("COREROUTER_NETNS_TESTS").is_none() {
        eprintln!("skipped: run inside a throwaway namespace (see the file's doc)");
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "add", "d0", "type", "dummy"]);
    ip(&["addr", "add", &format!("{ADDR}/24"), "dev", "d0"]);
    ip(&["link", "set", "d0", "up"]);

    let mut s = Session::virtual_lab();
    s.execute(
        "user.add",
        &json!({"name": "admin", "group": "full", "password": PW}),
    )
    .unwrap();
    let session = shared(s);
    let (cert, key) = corerouter_control::tls::generate().unwrap();
    let id = corerouter_control::tls::identity_from_pem(cert.as_bytes(), key.as_bytes()).unwrap();
    let listener = TcpListener::bind(format!("{ADDR}:0")).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let timeouts = Timeouts {
        keepalive_idle: Duration::from_secs(1),
        keepalive_interval: Duration::from_secs(1),
        keepalive_probes: 2,
        ..Timeouts::default()
    };
    spawn(
        Endpoint::tls(listener, id.config.clone()).with_timeouts(timeouts),
        SharedHost(session.clone()),
        Gate::default(),
    )
    .unwrap();
    let t = Duration::from_secs(2);

    // A stranger from the network: no build in server.info, and a long
    // line before login closes the connection.
    let mut stranger = Client::connect_tls(&addr, t, None).unwrap();
    let info = stranger.call("server.info", Value::Null).unwrap();
    assert_eq!(info["auth"], "required");
    assert!(
        info.get("commit").is_none() && info.get("version").is_none(),
        "{info}"
    );
    let e = stranger
        .call(
            "auth.login",
            json!({"user": "x".repeat(100 * 1024), "password": "y"}),
        )
        .unwrap_err();
    assert!(e.contains("before login"), "{e}");

    // The operator logs in (now the build is shown) and enters Safe Mode.
    let mut owner = Client::connect_tls(&addr, t, None).unwrap();
    owner.login("admin", PW).unwrap();
    assert!(
        owner
            .call("server.info", Value::Null)
            .unwrap()
            .get("commit")
            .is_some()
    );
    for (command, params) in [
        ("config.safe-mode.enter", json!({})),
        ("interface.set", json!({"name": "ether2", "disabled": true})),
    ] {
        owner
            .call(
                "engine.execute",
                json!({"command": command, "params": params}),
            )
            .unwrap();
    }
    assert!(ether2_disabled(&session));

    // The management address goes away under the open connection.
    ip(&["addr", "del", &format!("{ADDR}/24"), "dev", "d0"]);
    let start = Instant::now();
    while ether2_disabled(&session) && start.elapsed() < Duration::from_secs(20) {
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        !ether2_disabled(&session),
        "Safe Mode was not undone 20 s after the owner's path died"
    );
    eprintln!("undone after {:?}", start.elapsed());
    drop(owner);
}

//! G0.11: the local Unix socket, same user (the two-uid case is
//! `tests/unix_socket_root.rs`, as root in the lab VM).
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use corerouter_control::{Client, Gate, Limits, SharedHost, Shutdown, unix};
use corerouter_engine::{Session, Shared, shared};
use serde_json::{Value, json};

fn temp_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "cr-unix-{tag}-{}-{:?}",
        std::process::id(),
        Instant::now()
    ));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn lab() -> (Shared, Gate) {
    let mut s = Session::virtual_lab();
    s.execute(
        "user.add",
        &json!({"name": "noc", "group": "read", "password": "noc-password"}),
    )
    .unwrap();
    let gate = Gate::new(Limits {
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(2),
        ..Limits::default()
    });
    (shared(s), gate)
}

fn add(address: &str) -> Value {
    json!({"command": "ip.address.add", "params": {"address": address, "interface": "ether1"}})
}

fn wait_gone(p: &std::path::Path) -> bool {
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        if !p.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    false
}

#[test]
fn the_routers_user_is_local_without_a_token() {
    let dir = temp_dir("local");
    let path = dir.join("control-1.sock");
    let (session, gate) = lab();
    let l = unix::bind_at(&path).unwrap();
    // Private: the directory 0700, the socket 0600.
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&dir), 0o700);
    assert_eq!(mode(&path), 0o600);
    let stop = Shutdown::default();
    unix::spawn_until(l, SharedHost(session.clone()), gate.clone(), stop.clone()).unwrap();

    let mut c = Client::connect_unix(&path).unwrap();
    assert!(c.is_unix() && c.peer().is_none() && !c.is_stale());
    // No token: the OS user acts as the local principal (group full).
    let me = c.call("auth.whoami", Value::Null).unwrap();
    assert_eq!(me["group"], "full", "{me}");
    assert!(me["via"].as_str().unwrap().starts_with("unix uid="), "{me}");
    c.call("engine.execute", add("10.0.0.1/24")).unwrap();
    // server.info is the full one, as on loopback.
    let info = c.call("server.info", Value::Null).unwrap();
    assert!(info.get("version").is_some(), "{info}");
    // A login over the socket acts as that user from then on.
    let mut noc = Client::connect_unix(&path).unwrap();
    noc.login("noc", "noc-password").unwrap();
    let me = noc.call("auth.whoami", Value::Null).unwrap();
    assert_eq!(
        (me["user"].as_str(), me["group"].as_str()),
        (Some("noc"), Some("read"))
    );
    let e = noc.call("engine.execute", add("10.0.1.1/24")).unwrap_err();
    assert!(e.contains("needs group write"), "{e}");
    // A bad token is refused, not taken as the OS user.
    noc.set_token(Some("00".repeat(32)));
    assert!(noc.call("auth.whoami", Value::Null).is_err());

    // Hostile lines: not JSON closes the connection; others keep going.
    let mut raw = UnixStream::connect(&path).unwrap();
    raw.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    let mut line = String::new();
    let n = BufReader::new(&raw).read_line(&mut line).unwrap();
    assert_eq!(n, 0, "{line}");

    // Shutdown removes the socket.
    stop.close();
    assert!(wait_gone(&path), "socket left behind");
    // A newer router replaces a live socket (as the token file); the old
    // one, stopping, leaves the newer socket in place.
    let old = unix::bind_at(&path).unwrap();
    let old_stop = Shutdown::default();
    unix::spawn_until(
        old,
        SharedHost(session.clone()),
        gate.clone(),
        old_stop.clone(),
    )
    .unwrap();
    let new = unix::bind_at(&path).unwrap();
    old_stop.close();
    std::thread::sleep(Duration::from_millis(200));
    assert!(path.exists(), "the old router removed the new socket");
    drop(new);
    drop(c);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_stale_socket_is_replaced_and_a_file_is_not() {
    let dir = temp_dir("stale");
    let path = dir.join("control-2.sock");
    std::fs::create_dir_all(&dir).unwrap();
    // A socket nobody serves (a router that crashed).
    drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
    let l = unix::bind_at(&path).unwrap();
    drop(l);
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, b"not a socket").unwrap();
    let e = unix::bind_at(&path).err().unwrap();
    assert_eq!(e.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&path).unwrap(), b"not a socket");
    // A loose directory is made private again.
    std::fs::remove_file(&path).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let _l = unix::bind_at(&path).unwrap();
    let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn many_clients_at_once_get_a_slot_each_up_to_the_cap() {
    let dir = temp_dir("cap");
    let path = dir.join("control-3.sock");
    let (session, gate) = lab();
    let l = unix::bind_at(&path).unwrap();
    let stop = Shutdown::default();
    unix::spawn_until(l, SharedHost(session), gate, stop.clone()).unwrap();
    let mut held: Vec<Client> = (0..unix::MAX_PER_UID)
        .map(|_| Client::connect_unix(&path).unwrap())
        .collect();
    for c in &mut held {
        assert_eq!(c.call("ping", Value::Null).unwrap()["pong"], true);
    }
    // One more from the same user: told why.
    let mut extra = Client::connect_unix(&path).unwrap();
    let e = extra.call("ping", Value::Null).unwrap_err();
    assert!(e.contains("too many connections"), "{e}");
    // A slot comes back when a client leaves.
    held.pop();
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let mut c = Client::connect_unix(&path).unwrap();
        if c.call("ping", Value::Null).is_ok() {
            break;
        }
        assert!(Instant::now() < until, "the slot never came back");
        std::thread::sleep(Duration::from_millis(20));
    }
    stop.close();
    let _ = std::fs::remove_dir_all(&dir);
}

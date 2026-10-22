use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use corerouter_control::{Client, SharedHost, bind_loopback, spawn};
use corerouter_engine::{Session, shared};
use serde_json::{Value, json};

#[test]
fn roundtrip_and_hostile_lines() {
    let listener = bind_loopback(0).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    spawn(listener, SharedHost(shared(Session::virtual_lab()))).unwrap();

    let mut c = Client::connect(&addr, Duration::from_secs(2)).unwrap();
    assert_eq!(c.call("ping", Value::Null).unwrap()["pong"], true);
    let r = c
        .call(
            "engine.execute",
            json!({"command": "ip.address.add", "params": {"address": "192.0.2.1/24", "interface": "ether3"}}),
        )
        .unwrap();
    assert_eq!(r["id"], "*1");
    assert!(
        c.call("engine.execute", json!({"command": "nope"}))
            .is_err()
    );

    // An HTTP request is not JSON: the server must close the connection.
    let mut raw = TcpStream::connect(&addr).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    raw.write_all(b"POST / HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(raw.read(&mut buf).unwrap(), 0);
}

fn ether2_disabled(session: &corerouter_engine::Shared) -> bool {
    corerouter_engine::lock(session)
        .store()
        .running()
        .interfaces
        .values()
        .any(|i| i.name.as_str() == "ether2" && i.disabled)
}

/// G1.4: Safe Mode belongs to one connection; when it closes, the changes go.
#[test]
fn closing_the_safe_mode_connection_undoes_its_changes() {
    let listener = bind_loopback(0).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let session = shared(Session::virtual_lab());
    spawn(listener, SharedHost(session.clone())).unwrap();
    let execute = |c: &mut Client, command: &str, params: Value| {
        c.call(
            "engine.execute",
            json!({"command": command, "params": params}),
        )
    };

    let mut owner = Client::connect(&addr, Duration::from_secs(2)).unwrap();
    let mut other = Client::connect(&addr, Duration::from_secs(2)).unwrap();
    execute(&mut owner, "config.safe-mode.enter", json!({})).unwrap();
    execute(
        &mut owner,
        "interface.set",
        json!({"name": "ether2", "disabled": true}),
    )
    .unwrap();
    let mine = owner.call("state.inspect", json!({})).unwrap();
    assert_eq!(mine["safe_mode"]["yours"], true);
    let theirs = other.call("state.inspect", json!({})).unwrap();
    assert_eq!(theirs["safe_mode"]["yours"], false);
    let refused = execute(&mut other, "config.safe-mode.enter", json!({})).unwrap_err();
    assert!(refused.contains("held by tcp 127.0.0.1:"), "{refused}");

    // A bystander leaving changes nothing.
    drop(other);
    std::thread::sleep(Duration::from_millis(200));
    assert!(ether2_disabled(&session));

    drop(owner);
    let until = std::time::Instant::now() + Duration::from_secs(5);
    while ether2_disabled(&session) && std::time::Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!ether2_disabled(&session), "the owner's hang-up must undo");
    assert!(!corerouter_engine::lock(&session).in_safe_mode());
}

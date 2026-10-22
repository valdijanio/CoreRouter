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

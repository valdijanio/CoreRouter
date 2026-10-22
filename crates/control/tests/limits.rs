//! Control audit (findings 2, 8, 3, 11, 12): connection slots, deadlines, idle limits and panics on the
//! control endpoints. Timeouts are shortened per endpoint so each test
//! takes about a second.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use corerouter_control::server::MAX_CONNECTIONS;
use corerouter_control::{
    Client, Endpoint, Gate, Host, Limits, SharedHost, Timeouts, WsPolicy, bind_loopback, spawn,
    spawn_ws,
};
use corerouter_engine::{Session, Shared, shared};
use serde_json::{Value, json};

const ADMIN_PW: &str = "admin-password";

fn lab() -> (Shared, Gate, String) {
    let mut s = Session::virtual_lab();
    s.execute(
        "user.add",
        &json!({"name": "admin", "group": "full", "password": ADMIN_PW}),
    )
    .unwrap();
    let gate = Gate::new(Limits {
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(2),
        ..Limits::default()
    });
    let token = corerouter_control::auth::new_token().unwrap();
    gate.add_local_token(&token);
    (shared(s), gate, token)
}

fn quick() -> Timeouts {
    Timeouts {
        handshake: Duration::from_millis(500),
        unauthenticated_idle: Duration::from_millis(300),
        ..Timeouts::default()
    }
}

fn tls_endpoint(session: &Shared, gate: &Gate) -> String {
    let (cert, key) = corerouter_control::tls::generate().unwrap();
    let id = corerouter_control::tls::identity_from_pem(cert.as_bytes(), key.as_bytes()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    spawn(
        Endpoint::tls(listener, id.config.clone()).with_timeouts(quick()),
        SharedHost(session.clone()),
        gate.clone(),
    )
    .unwrap();
    addr
}

/// Read until the server closes (0 or an error), or `None` after `within`.
fn closed_within(s: &mut TcpStream, within: Duration) -> Option<Duration> {
    let start = Instant::now();
    s.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
    let mut buf = [0u8; 4096];
    while start.elapsed() < within {
        match s.read(&mut buf) {
            Ok(0) => return Some(start.elapsed()),
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => return Some(start.elapsed()),
        }
    }
    None
}

/// 16 strangers finish the TLS handshake and then say nothing: they used
/// to hold every slot forever. Now they are dropped after the logged-out
/// idle time, and only half the slots can be logged out at once.
#[test]
fn idle_strangers_do_not_lock_the_operator_out() {
    let (session, gate, _) = lab();
    let addr = tls_endpoint(&session, &gate);
    let mut idle = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        let tcp = TcpStream::connect(&addr).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        // Refused ones fail the handshake; the rest stay silent.
        if let Ok((s, _)) = corerouter_control::tls::connect(tcp, None) {
            idle.push(s);
        }
    }
    assert!(
        idle.len() <= corerouter_control::conn::MAX_UNAUTHENTICATED,
        "{} logged-out connections held",
        idle.len()
    );
    std::thread::sleep(Duration::from_millis(700));
    let mut c = Client::connect_tls(&addr, Duration::from_secs(2), None).unwrap();
    c.login("admin", ADMIN_PW).unwrap();
    assert_eq!(c.call("ping", Value::Null).unwrap()["pong"], true);
    // Logged in: no idle limit any more.
    std::thread::sleep(Duration::from_millis(700));
    assert_eq!(c.call("auth.whoami", Value::Null).unwrap()["user"], "admin");
    drop(idle);
}

/// A ClientHello trickled one byte at a time: the handshake has a deadline
/// for the whole, not a timeout per read.
#[test]
fn a_trickled_tls_handshake_is_cut_at_the_deadline() {
    let (session, gate, _) = lab();
    let addr = tls_endpoint(&session, &gate);
    let mut s = TcpStream::connect(&addr).unwrap();
    // Record header of a 512-byte handshake record; then one byte per 100 ms.
    s.write_all(&[0x16, 0x03, 0x01, 0x02, 0x00]).unwrap();
    let mut writer = s.try_clone().unwrap();
    let feeder = std::thread::spawn(move || {
        for _ in 0..40 {
            if writer.write_all(&[0]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    let t = closed_within(&mut s, Duration::from_secs(3));
    assert!(t.is_some(), "still open after 3 s");
    feeder.join().unwrap();
}

/// The same for the HTTP head of a WebSocket port, and the logged-out
/// connections over the limit get a real `503`.
#[test]
fn websocket_head_deadline_and_503() {
    let (session, gate, _) = lab();
    let listener = bind_loopback(0).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    spawn_ws(
        Endpoint::loopback(listener).with_timeouts(quick()),
        SharedHost(session.clone()),
        WsPolicy::default(),
        gate.clone(),
    )
    .unwrap();
    let mut s = TcpStream::connect(&addr).unwrap();
    let mut writer = s.try_clone().unwrap();
    let feeder = std::thread::spawn(move || {
        for b in b"GET / HTTP/1.1\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
            if writer.write_all(&[*b]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    });
    assert!(closed_within(&mut s, Duration::from_secs(3)).is_some());
    feeder.join().unwrap();

    let held: Vec<TcpStream> = (0..corerouter_control::conn::MAX_UNAUTHENTICATED)
        .map(|_| TcpStream::connect(&addr).unwrap())
        .collect();
    std::thread::sleep(Duration::from_millis(50));
    let mut over = TcpStream::connect(&addr).unwrap();
    over.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut reply = String::new();
    let _ = over.read_to_string(&mut reply);
    assert!(reply.starts_with("HTTP/1.1 503"), "{reply}");
    drop(held);
}

/// A host whose `forward` panics on `engine.list`: a panic outside the
/// engine's guard, as rustls, tungstenite or a GUI host could raise.
#[derive(Clone)]
struct Panicky(SharedHost);

impl Host for Panicky {
    fn with_session(
        &mut self,
        f: &mut dyn FnMut(&mut Session) -> Result<Value, String>,
    ) -> Result<Value, String> {
        self.0.with_session(f)
    }

    fn forward(&mut self, method: &str, _params: &Value) -> Option<Result<Value, String>> {
        if method == "engine.list" {
            panic!("boom (test)");
        }
        None
    }
}

fn ether2_disabled(session: &Shared) -> bool {
    corerouter_engine::lock(session)
        .store()
        .running()
        .interfaces
        .values()
        .any(|i| i.name.as_str() == "ether2" && i.disabled)
}

/// A panicking connection thread gives its slot back and still undoes its
/// Safe Mode.
#[test]
fn a_panicking_connection_frees_its_slot_and_undoes_safe_mode() {
    let (session, gate, token) = lab();
    let listener = bind_loopback(0).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    spawn(
        Endpoint::loopback(listener),
        Panicky(SharedHost(session.clone())),
        gate.clone(),
    )
    .unwrap();
    let local = || {
        let mut c = Client::connect(&addr, Duration::from_secs(2)).unwrap();
        c.set_token(Some(token.clone()));
        c
    };
    let mut owner = local();
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
    assert!(owner.call("engine.list", Value::Null).is_err());
    let until = Instant::now() + Duration::from_secs(5);
    while ether2_disabled(&session) && Instant::now() < until {
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(!ether2_disabled(&session), "the panic skipped hang_up");
    for _ in 0..MAX_CONNECTIONS + 2 {
        assert!(local().call("engine.list", Value::Null).is_err());
    }
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(local().call("ping", Value::Null).unwrap()["pong"], true);
}

/// The token is checked before `params` are turned into JSON values: a
/// stranger's 16 MiB array is never parsed (it used to become hundreds of
/// MiB of `Value`s first). Seen from outside: `params` that only the full
/// parse rejects (a number out of `f64` range) still get "unauthorized"
/// without a token, and the parse error only with one.
#[test]
fn params_are_parsed_only_after_the_token_check() {
    let (session, gate, token) = lab();
    let listener = bind_loopback(0).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    spawn(Endpoint::loopback(listener), SharedHost(session), gate).unwrap();
    let mut s = TcpStream::connect(&addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let mut reader = std::io::BufReader::new(s.try_clone().unwrap());
    let mut ask = |line: String| {
        s.write_all(line.as_bytes()).unwrap();
        let mut reply = String::new();
        std::io::BufRead::read_line(&mut reader, &mut reply).unwrap();
        serde_json::from_str::<Value>(&reply).unwrap()
    };
    let r = ask("{\"id\":1,\"method\":\"engine.execute\",\"params\":1e999}\n".into());
    assert!(
        r["error"].as_str().unwrap().starts_with("unauthorized"),
        "{r}"
    );
    let r = ask(format!(
        "{{\"id\":2,\"method\":\"engine.execute\",\"params\":1e999,\"token\":\"{token}\"}}\n"
    ));
    assert!(r["error"].as_str().unwrap().starts_with("params:"), "{r}");
    // A huge id is not echoed.
    let r = ask(format!(
        "{{\"id\":\"{}\",\"method\":\"ping\"}}\n",
        "x".repeat(4096)
    ));
    assert_eq!((&r["id"], &r["ok"]), (&Value::Null, &json!(true)));
}

/// `server.info` still answers loopback clients in full before login (the
/// GUI's connection screen reads `auth` and `version` from it).
#[test]
fn server_info_on_loopback_is_complete() {
    let (session, gate, _) = lab();
    let listener = bind_loopback(0).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    spawn(Endpoint::loopback(listener), SharedHost(session), gate).unwrap();
    let mut c = Client::connect(&addr, Duration::from_secs(2)).unwrap();
    let info = c.call("server.info", Value::Null).unwrap();
    assert_eq!(info["auth"], "required");
    assert!(info.get("version").is_some() && info.get("commit").is_some());
}

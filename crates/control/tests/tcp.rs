#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use corerouter_control::dial::{Expect, RefuseNew};
use corerouter_control::{
    Client, Endpoint, Gate, KnownHosts, Limits, Login, SharedHost, Target, Trust, UNAUTHORIZED,
    bind_loopback, dial, spawn,
};
use corerouter_engine::{Session, Shared, shared};
use serde_json::{Value, json};

const ADMIN_PW: &str = "admin-password";

/// A lab with admin (full) and noc (read), a gate with a known local token.
fn lab() -> (Shared, Gate, String) {
    let mut s = Session::virtual_lab();
    for (name, group) in [("admin", "full"), ("noc", "read")] {
        s.execute(
            "user.add",
            &json!({"name": name, "group": group, "password": ADMIN_PW}),
        )
        .unwrap();
    }
    let gate = Gate::new(Limits {
        base_delay: Duration::from_millis(1),
        max_delay: Duration::from_millis(2),
        ..Limits::default()
    });
    let token = corerouter_control::auth::new_token().unwrap();
    gate.add_local_token(&token);
    (shared(s), gate, token)
}

fn start(session: &Shared, gate: &Gate) -> String {
    let listener = bind_loopback(0).unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    spawn(
        Endpoint::loopback(listener),
        SharedHost(session.clone()),
        gate.clone(),
    )
    .unwrap();
    addr
}

fn local(addr: &str, token: &str) -> Client {
    let mut c = Client::connect(addr, Duration::from_secs(2)).unwrap();
    c.set_token(Some(token.to_owned()));
    c
}

#[test]
fn roundtrip_and_hostile_lines() {
    let (session, gate, token) = lab();
    let addr = start(&session, &gate);
    let mut c = local(&addr, &token);
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
    assert_eq!(c.call("auth.whoami", Value::Null).unwrap()["user"], "local");

    // An HTTP request is not JSON: the server must close the connection.
    let mut raw = TcpStream::connect(&addr).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    raw.write_all(b"POST / HTTP/1.1\r\nHost: x\r\n\r\n")
        .unwrap();
    let mut buf = [0u8; 16];
    assert_eq!(raw.read(&mut buf).unwrap(), 0);
}

/// G0.3: loopback without a credential gets nothing but ping/server.info.
#[test]
fn loopback_without_credentials_is_refused() {
    let (session, gate, _) = lab();
    let addr = start(&session, &gate);
    let mut c = Client::connect(&addr, Duration::from_secs(2)).unwrap();
    assert_eq!(c.call("ping", Value::Null).unwrap()["pong"], true);
    assert_eq!(
        c.call("server.info", Value::Null).unwrap()["auth"],
        "required"
    );
    for (method, params) in [
        ("engine.list", Value::Null),
        ("state.inspect", json!({})),
        (
            "engine.execute",
            json!({"command": "system.identity.set", "params": {"name": "pwned"}}),
        ),
        ("engine.batch", json!({"steps": []})),
    ] {
        let e = c.call(method, params).unwrap_err();
        assert!(e.starts_with(UNAUTHORIZED), "{method}: {e}");
    }
    c.set_token(Some("f".repeat(64)));
    assert!(
        c.call("engine.list", Value::Null)
            .unwrap_err()
            .starts_with(UNAUTHORIZED)
    );
    assert_eq!(
        corerouter_engine::lock(&session)
            .store()
            .running()
            .system
            .identity,
        "CoreRouter"
    );
}

#[test]
fn login_and_group_permissions_over_the_wire() {
    let (session, gate, _) = lab();
    let addr = start(&session, &gate);
    let mut c = Client::connect(&addr, Duration::from_secs(2)).unwrap();
    let e = c.login("admin", "wrong-password").unwrap_err();
    assert_eq!(e, "invalid user or password");
    let e = c.login("nobody", ADMIN_PW).unwrap_err();
    assert_eq!(e, "invalid user or password");
    let me = c.login("noc", ADMIN_PW).unwrap();
    assert_eq!(me["group"], "read");
    assert!(c.call("state.inspect", json!({})).is_ok());
    let e = c
        .call(
            "engine.execute",
            json!({"command": "system.identity.set", "params": {"name": "x"}}),
        )
        .unwrap_err();
    assert!(e.contains("needs group write"), "{e}");
    let list = c.call("engine.list", Value::Null).unwrap();
    let add = list
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["id"] == "ip.address.add")
        .unwrap();
    assert_eq!(add["enabled"], false);
    // The admin sees noc's session; logout ends it.
    let mut admin = Client::connect(&addr, Duration::from_secs(2)).unwrap();
    admin.login("admin", ADMIN_PW).unwrap();
    let active = admin
        .call("engine.execute", json!({"command": "user.active.list"}))
        .unwrap();
    assert!(active.to_string().contains("noc"), "{active}");
    c.call("auth.logout", Value::Null).unwrap();
    assert!(
        c.call("state.inspect", json!({}))
            .unwrap_err()
            .starts_with(UNAUTHORIZED)
    );
    // A password never shows in the journal the admin can read.
    admin
        .call(
            "engine.execute",
            json!({"command": "user.add", "params": {"name": "bob", "group": "write", "password": "bobs-password"}}),
        )
        .unwrap();
    let journal = admin
        .call("state.inspect", json!({"path": "journal"}))
        .unwrap();
    assert!(!journal.to_string().contains("bobs-password"));
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
    let (session, gate, token) = lab();
    let addr = start(&session, &gate);
    let execute = |c: &mut Client, command: &str, params: Value| {
        c.call(
            "engine.execute",
            json!({"command": command, "params": params}),
        )
    };

    let mut owner = local(&addr, &token);
    let mut other = local(&addr, &token);
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

/// G2.1b: the control channel tells the engine which connection a command
/// came from, so a rule that would drop it (loopback here: `lo`) is refused
/// with the lockout reason, and `force` goes through.
#[test]
fn a_rule_that_drops_this_connection_is_refused_over_the_wire() {
    let (session, gate, token) = lab();
    let addr = start(&session, &gate);
    let mut c = local(&addr, &token);
    let drop_lo = json!({"chain": "input", "action": "drop", "in_interface": "lo"});
    let refused = c
        .call(
            "engine.execute",
            json!({"command": "ip.firewall.filter.add", "params": drop_lo}),
        )
        .unwrap_err();
    assert!(refused.starts_with("lockout: "), "{refused}");
    assert!(refused.contains("in-interface=lo"), "{refused}");
    assert!(refused.contains(&format!("-> {addr} on lo")), "{refused}");
    let mut forced = drop_lo.clone();
    forced["force"] = json!(true);
    c.call(
        "engine.execute",
        json!({"command": "ip.firewall.filter.add", "params": forced}),
    )
    .unwrap();
}

/// TLS end to end on loopback: TOFU (first time, same, changed), login.
#[test]
fn tls_endpoint_with_pinning_and_login() {
    let (session, gate, _) = lab();
    let (cert, key) = corerouter_control::tls::generate().unwrap();
    let id = corerouter_control::tls::identity_from_pem(cert.as_bytes(), key.as_bytes()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    spawn(
        Endpoint::tls(listener, id.config.clone()),
        SharedHost(session.clone()),
        gate.clone(),
    )
    .unwrap();
    let target = Target::parse(&format!("tls://127.0.0.1:{port}")).unwrap();
    let login = Login::Password {
        user: "admin".into(),
        password: ADMIN_PW.into(),
    };
    let dir = std::env::temp_dir().join(format!("cr-tofu-{}-{port}", std::process::id()));
    let path = dir.join("known_hosts");
    let mut known = KnownHosts::load(&path);
    let t = Duration::from_secs(2);

    // First use, refused: nothing is remembered.
    let e = dial(&target, t, &login, &mut known, &mut RefuseNew)
        .err()
        .unwrap();
    assert!(e.contains("not trusted"), "{e}");
    assert!(known.get(&target.addr()).is_none());

    // First use, accepted after showing the fingerprint.
    struct Shown(Option<String>);
    impl Trust for Shown {
        fn first_use(&mut self, _: &Target, fp: &str) -> bool {
            self.0 = Some(fp.to_owned());
            true
        }
    }
    let mut shown = Shown(None);
    let mut c = dial(&target, t, &login, &mut known, &mut shown).unwrap();
    assert_eq!(shown.0.as_deref(), Some(id.fingerprint.as_str()));
    assert_eq!(c.call("auth.whoami", Value::Null).unwrap()["user"], "admin");
    assert!(c.is_tls());

    // Same certificate: no question asked.
    let mut known = KnownHosts::load(&path);
    assert!(dial(&target, t, &login, &mut known, &mut RefuseNew).is_ok());
    assert!(
        dial(
            &target,
            t,
            &login,
            &mut KnownHosts::in_memory(),
            &mut Expect(id.fingerprint.clone())
        )
        .is_ok()
    );

    // The router's certificate changes: refused before logging in.
    known.remember(&target.addr(), "SHA256:00:11").unwrap();
    let e = dial(&target, t, &login, &mut known, &mut shown)
        .err()
        .unwrap();
    assert!(e.contains("CHANGED"), "{e}");

    // Plain text to a TLS port goes nowhere.
    let mut raw = TcpStream::connect(("127.0.0.1", port)).unwrap();
    raw.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    // The server may reset the connection before this write finishes; that
    // is the expected outcome, not a test failure.
    let _ = writeln!(raw, "{}", json!({"id": 1, "method": "ping"}));
    let mut line = String::new();
    let _ = BufReader::new(raw).read_line(&mut line);
    assert!(!line.contains("pong"));
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn shutdown_stops_accepting_and_closes_the_port() {
    use corerouter_control::{Shutdown, WsPolicy, serve_until, spawn_ws_until};
    let (session, gate, token) = lab();
    let shutdown = Shutdown::default();
    let tcp = bind_loopback(0).unwrap();
    let ws = bind_loopback(0).unwrap();
    let (tcp_addr, ws_addr) = (tcp.local_addr().unwrap(), ws.local_addr().unwrap());
    let (host, stop, g) = (SharedHost(session.clone()), shutdown.clone(), gate.clone());
    let control = std::thread::spawn(move || serve_until(Endpoint::loopback(tcp), host, g, &stop));
    let ws_thread = spawn_ws_until(
        Endpoint::loopback(ws),
        SharedHost(session),
        WsPolicy::default(),
        gate.clone(),
        shutdown.clone(),
    )
    .unwrap();
    // Open before the shutdown: keeps working.
    let mut open = local(&tcp_addr.to_string(), &token);
    assert_eq!(open.call("ping", Value::Null).unwrap()["pong"], true);

    shutdown.close();
    control.join().unwrap();
    ws_thread.join().unwrap();
    assert!(TcpStream::connect_timeout(&tcp_addr, Duration::from_secs(1)).is_err());
    assert!(TcpStream::connect_timeout(&ws_addr, Duration::from_secs(1)).is_err());
    assert_eq!(open.call("ping", Value::Null).unwrap()["pong"], true);
    // Closing twice, or a loop started after the close, returns at once.
    shutdown.close();
    serve_until(
        Endpoint::loopback(bind_loopback(0).unwrap()),
        SharedHost(shared(Session::virtual_lab())),
        gate,
        &shutdown,
    );
}

/// Median time of `n` sequential calls on one open connection.
/// The fastest of `n` calls. Nagle's ~40 ms delay hits every request, while
/// a loaded machine (parallel builds: `docs/perf.md`) only slows some, so the
/// fastest one still tells the two apart; a median failed under load.
fn fastest_call(c: &mut Client, method: &str, n: usize) -> Duration {
    let times: Vec<Duration> = (0..n)
        .map(|_| {
            let t = std::time::Instant::now();
            c.call(method, json!({})).unwrap();
            t.elapsed()
        })
        .collect();
    times.into_iter().min().unwrap_or(Duration::MAX)
}

/// One request per line must leave in one write: a reply split in two
/// (JSON, then "\n") waited for the peer's delayed ACK (Nagle), ~40 ms per
/// request. Plain TCP and TLS, server and client side.
#[test]
fn a_persistent_connection_answers_in_milliseconds() {
    // Half of Nagle's ~40 ms: a regression fails, a busy machine does not.
    const LIMIT: Duration = Duration::from_millis(20);
    let (session, gate, token) = lab();
    let addr = start(&session, &gate);
    let mut c = local(&addr, &token);
    let plain = fastest_call(&mut c, "ping", 40);
    let inspect = fastest_call(&mut c, "state.inspect", 40);

    let (cert, key) = corerouter_control::tls::generate().unwrap();
    let id = corerouter_control::tls::identity_from_pem(cert.as_bytes(), key.as_bytes()).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let tls_addr = listener.local_addr().unwrap().to_string();
    spawn(
        Endpoint::tls(listener, id.config.clone()),
        SharedHost(session.clone()),
        gate.clone(),
    )
    .unwrap();
    let mut t =
        Client::connect_tls(&tls_addr, Duration::from_secs(2), Some(&id.fingerprint)).unwrap();
    t.login("admin", ADMIN_PW).unwrap();
    let tls = fastest_call(&mut t, "ping", 40);
    eprintln!(
        "fastest request: tcp ping {plain:?}, tcp state.inspect {inspect:?}, tls ping {tls:?}"
    );
    for (what, d) in [
        ("tcp ping", plain),
        ("tcp inspect", inspect),
        ("tls ping", tls),
    ] {
        assert!(
            d < LIMIT,
            "{what}: fastest request took {d:?} (limit {LIMIT:?})"
        );
    }
}

//! G0.3: the CLI and its MCP server on the router's machine get in with the
//! local token file, and without it they are refused with a clear hint.
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use corerouter_control::{Endpoint, Gate, SharedHost, bind_loopback, spawn};
use corerouter_engine::{Session, shared};
use serde_json::{Value, json};

const CLI: &str = env!("CARGO_BIN_EXE_corerouter-cli");

/// A router on a loopback port; its token is written in `dir` as the
/// daemon would (`control-<port>.token`).
fn router(dir: &Path) -> u16 {
    let listener = bind_loopback(0).unwrap();
    let port = listener.local_addr().unwrap().port();
    let gate = Gate::default();
    let token = corerouter_control::auth::new_token().unwrap();
    gate.add_local_token(&token);
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join(format!("control-{port}.token")), &token).unwrap();
    spawn(
        Endpoint::loopback(listener),
        SharedHost(shared(Session::virtual_lab())),
        gate,
    )
    .unwrap();
    port
}

fn cli(runtime: &Path, args: &[&str]) -> (bool, String, String) {
    let out = Command::new(CLI)
        .args(args)
        .env("COREROUTER_RUNTIME_DIR", runtime)
        .env_remove("COREROUTER_PASSWORD")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn cli_and_mcp_use_the_local_token() {
    let base = std::env::temp_dir().join(format!("cr-cli-local-{}", std::process::id()));
    let runtime = base.join("run");
    let port = router(&runtime);
    let addr = format!("127.0.0.1:{port}");

    let (ok, out, err) = cli(
        &runtime,
        &[
            "--connect",
            &addr,
            "run",
            "system.identity.set",
            r#"{"name":"cli"}"#,
        ],
    );
    assert!(ok, "{err}");
    assert!(out.contains("\"cli\""), "{out}");

    // Another OS user has no token file: refused, and told why.
    let (ok, _, err) = cli(&base.join("elsewhere"), &["--connect", &addr, "inspect"]);
    assert!(!ok);
    assert!(err.contains("no local token"), "{err}");

    // A remote address needs --user (TLS + login).
    let (ok, _, err) = cli(&runtime, &["--connect", "192.0.2.1:8729", "inspect"]);
    assert!(!ok && err.contains("--user"), "{err}");

    // MCP over the same path.
    let mut child = Command::new(CLI)
        .args(["mcp", "--connect", &addr])
        .env("COREROUTER_RUNTIME_DIR", &runtime)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    for msg in [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"inspect_state","arguments":{}}}),
    ] {
        writeln!(stdin, "{msg}").unwrap();
    }
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let reply: Value = text
        .lines()
        .filter_map(|l| serde_json::from_str::<Value>(l).ok())
        .find(|v| v["id"] == 2)
        .unwrap_or_else(|| panic!("no reply: {text} {}", String::from_utf8_lossy(&out.stderr)));
    assert!(reply.to_string().contains("cli"), "{reply}");
    assert_ne!(reply["result"]["isError"], true, "{reply}");
    let _ = std::fs::remove_dir_all(base);
}

/// G0.3d: without a terminal a CHANGED certificate is refused with the way
/// out (`--accept-new-cert`), in `run` and in `mcp`; with the flag the CLI
/// connects and the known hosts line is replaced.
#[test]
fn a_changed_certificate_needs_accept_new_cert_without_a_terminal() {
    let base = std::env::temp_dir().join(format!("cr-cli-cert-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    let mut s = Session::virtual_lab();
    s.execute(
        "user.add",
        &json!({"name": "admin", "group": "full", "password": "cert-test-pw"}),
    )
    .unwrap();
    let (cert, key) = corerouter_control::tls::generate().unwrap();
    let id = corerouter_control::tls::identity_from_pem(cert.as_bytes(), key.as_bytes()).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    spawn(
        Endpoint::tls(listener, id.config.clone()),
        SharedHost(shared(s)),
        Gate::default(),
    )
    .unwrap();
    let known = base.join("known_hosts");
    std::fs::write(&known, format!("{addr} SHA256:00:11 1700000000\n")).unwrap();
    let target = format!("tls://{addr}");
    let run = |extra: &[&str]| {
        let out = Command::new(CLI)
            .args(["--connect", &target, "--user", "admin"])
            .args(extra)
            .env("COREROUTER_KNOWN_HOSTS", &known)
            .env("COREROUTER_PASSWORD", "cert-test-pw")
            .stdin(Stdio::null())
            .output()
            .unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    };
    for args in [&["inspect"][..], &["mcp"][..]] {
        let (ok, err) = run(args);
        assert!(!ok, "{args:?}");
        assert!(
            err.contains("CHANGED") && err.contains("--accept-new-cert"),
            "{args:?}: {err}"
        );
    }
    assert!(
        std::fs::read_to_string(&known)
            .unwrap()
            .contains("SHA256:00:11")
    );
    let (ok, err) = run(&["--accept-new-cert", "run", "system.identity.get"]);
    assert!(ok, "{err}");
    let text = std::fs::read_to_string(&known).unwrap();
    assert!(
        text.contains(&format!("{addr} {}", id.fingerprint)),
        "{text}"
    );
    assert!(!text.contains("SHA256:00:11"), "{text}");
    // Now known: no flag needed.
    let (ok, err) = run(&["run", "system.identity.get"]);
    assert!(ok, "{err}");
    let _ = std::fs::remove_dir_all(&base);
}

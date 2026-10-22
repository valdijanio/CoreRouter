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

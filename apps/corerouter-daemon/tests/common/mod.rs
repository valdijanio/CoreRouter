//! Helpers shared by the daemon's network-namespace tests (`netns.rs`,
//! `netns_l2.rs`). Helpers outside `#[test]` fns may unwrap/panic.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use corerouter_control::Client;
use serde_json::{Value, json};

pub const ENV: &str = "COREROUTER_NETNS_TESTS";
/// Set by [`call`] when it re-runs the test binary inside B's namespace.
const QUERY_ENV: &str = "CRDP_NETNS_QUERY";
const QUERY_CMD_ENV: &str = "CRDP_NETNS_QUERY_CMD";
const QUERY_TOKEN_ENV: &str = "CRDP_NETNS_QUERY_TOKEN";
pub const DAEMON: &str = env!("CARGO_BIN_EXE_corerouter-daemon");
pub const CONTROL: &str = "127.0.0.1:7979";

/// True when the test may touch the kernel; panics outside a fresh namespace.
pub fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!(
            "skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net` \
             (cargo xtask netns)"
        );
        return false;
    }
    let names = link_names();
    assert_eq!(
        names,
        ["lo"],
        "{ENV}=1 but this network namespace has {names:?}, not just lo; refusing to touch it"
    );
    true
}

fn link_names() -> Vec<String> {
    let out = Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split(':').nth(1))
        .map(|n| n.trim().split('@').next().unwrap_or("").to_owned())
        .collect()
}

/// A command run here, or inside the network namespace of `pid`.
pub fn in_ns(pid: Option<u32>, program: &str) -> Command {
    match pid {
        Some(pid) => {
            let mut c = Command::new("nsenter");
            c.args(["--target", &pid.to_string(), "--net", "--", program]);
            c
        }
        None => Command::new(program),
    }
}

/// `ip …` here, or inside namespace `pid`.
pub fn ip(pid: Option<u32>, args: &[&str]) {
    let out = in_ns(pid, "ip").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "ip {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Kills the process when the test ends, pass or fail.
pub struct Kill(pub Child);

impl Drop for Kill {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn netns_of(pid: u32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/{pid}/ns/net")).ok()
}

/// A second network namespace ("B"), held open by a sleeper; join it with
/// [`in_ns`] and its pid.
pub fn namespace_b() -> Kill {
    let holder = Kill(
        Command::new("unshare")
            .args(["--net", "--", "sleep", "300"])
            .spawn()
            .unwrap(),
    );
    let b = holder.0.id();
    let here = netns_of(std::process::id());
    wait_for("B's namespace", || {
        netns_of(b).is_some_and(|ns| Some(ns) != here)
    });
    holder
}

/// Token files of the daemons, by namespace (G0.3: each daemon writes its
/// local token to `--token-file`, see [`token_file`]).
static TOKENS: std::sync::Mutex<Vec<(Option<u32>, PathBuf)>> = std::sync::Mutex::new(Vec::new());

/// The `--token-file` of a daemon whose config dir is `dir`, remembered
/// for [`call`] on namespace `netns`.
pub fn token_file(netns: Option<u32>, dir: &std::path::Path) -> PathBuf {
    let path = dir.join("local.token");
    let mut t = TOKENS.lock().unwrap();
    t.retain(|(n, _)| *n != netns);
    t.push((netns, path.clone()));
    path
}

pub fn token_of(netns: Option<u32>) -> Option<String> {
    let t = TOKENS.lock().unwrap();
    let path = t
        .iter()
        .find(|(n, _)| *n == netns)
        .map(|(_, p)| p.clone())?;
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_owned())
}

/// A client of the control port at `addr` with `token`.
pub fn client(addr: &str, token: Option<String>) -> Result<Client, String> {
    let mut c = Client::connect(addr, Duration::from_secs(1))?;
    c.set_token(token);
    Ok(c)
}

/// `engine.execute {command, params}` on router A (here) or B (inside
/// `pid`, by re-running this test binary there: see [`query_helper`]).
pub fn call(netns: Option<u32>, command: &str, params: Value) -> Result<Value, String> {
    let req = json!({"command": command, "params": params});
    match netns {
        None => client(CONTROL, token_of(None)).and_then(|mut c| c.call("engine.execute", req)),
        Some(pid) => {
            let out = in_ns(
                Some(pid),
                &std::env::current_exe().unwrap().to_string_lossy(),
            )
            .args([
                "query_helper",
                "--exact",
                "--nocapture",
                "--test-threads",
                "1",
            ])
            .env(QUERY_ENV, CONTROL)
            .env(QUERY_CMD_ENV, req.to_string())
            .env(QUERY_TOKEN_ENV, token_of(Some(pid)).unwrap_or_default())
            .env_remove(ENV)
            .output()
            .unwrap();
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.lines()
                .find_map(|l| l.split_once("QUERY-RESULT ").map(|(_, j)| j))
                .ok_or_else(|| format!("no result from B: {text}"))
                .and_then(|j| serde_json::from_str::<Value>(j).map_err(|e| e.to_string()))
                .and_then(|v| match v {
                    Value::Object(mut o) if o.contains_key("error") => {
                        Err(o.remove("error").map(|e| e.to_string()).unwrap_or_default())
                    }
                    other => Ok(other),
                })
        }
    }
}

/// Body of each test binary's `query_helper` (not a test: run inside B by
/// [`call`]).
pub fn query_helper() {
    let Ok(addr) = std::env::var(QUERY_ENV) else {
        return;
    };
    let req: Value = std::env::var(QUERY_CMD_ENV)
        .ok()
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_else(|| json!({"command": "ip.neighbor.list"}));
    let token = std::env::var(QUERY_TOKEN_ENV)
        .ok()
        .filter(|t| !t.is_empty());
    let answer = client(&addr, token).and_then(|mut c| c.call("engine.execute", req));
    let line = match answer {
        Ok(v) => v,
        Err(e) => json!({ "error": e }),
    };
    println!("QUERY-RESULT {line}");
}

/// `ip.neighbor.list` of router A (here) or B (inside `pid`); empty (and
/// logged) when the router does not answer yet.
pub fn neighbors(netns: Option<u32>) -> Vec<Value> {
    neighbors_with(netns, json!({}))
}

pub fn neighbors_with(netns: Option<u32>, params: Value) -> Vec<Value> {
    match call(netns, "ip.neighbor.list", params) {
        Ok(Value::Array(rows)) => rows,
        other => {
            eprintln!("ip.neighbor.list in {netns:?}: {other:?}");
            Vec::new()
        }
    }
}

pub fn wait_for(what: &str, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    panic!("timed out waiting for {what}");
}

pub fn sees<'a>(rows: &'a [Value], identity: &str) -> Option<&'a Value> {
    rows.iter().find(|r| r["identity"] == identity)
}

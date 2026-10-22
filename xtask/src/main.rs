//! `cargo xtask <task>` — checks as code. Agents run `cargo xtask ci` before
//! every commit; it stops at the first FAIL and prints an ok/FAIL/skip summary.

mod bench;
mod layers;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const USAGE: &str = "usage: cargo xtask <ci|fmt|clippy|test|bench-check|netns|layers|agents-sync|wasm|bench [--help]>";

/// Crates that must keep compiling for the browser.
const WASM_PACKAGES: &[&str] = &[
    "corerouter-model",
    "corerouter-hal",
    "corerouter-proto-lldp",
    "corerouter-proto-mndp",
    "corerouter-engine",
    "corerouter-shell",
    "corerouter-ui",
    "corerouter-gui",
];
const WASM_TARGET: &str = "wasm32-unknown-unknown";

enum Outcome {
    Ok,
    Fail(String),
    Skip(String),
}

type Step = (&'static str, fn(&Path) -> Outcome);

const CI: &[Step] = &[
    ("fmt", fmt),
    ("clippy", clippy),
    ("test", test),
    // G0.9: every benchmark compiled and run once in debug (no measurement),
    // so a renamed command parameter fails here instead of rotting.
    ("bench-check", bench::check),
    ("netns", netns),
    ("layers", layers_step),
    ("agents-sync", agents_sync),
    ("wasm", wasm),
];

fn main() -> ExitCode {
    let root = workspace_root();
    let task = std::env::args().nth(1).unwrap_or_default();
    let steps: Vec<&Step> = match task.as_str() {
        "ci" => CI.iter().collect(),
        "bench" => {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            return match bench::main(&root, &rest) {
                Outcome::Ok => ExitCode::SUCCESS,
                Outcome::Skip(why) => {
                    eprintln!("skip: {why}");
                    ExitCode::SUCCESS
                }
                Outcome::Fail(why) => {
                    eprintln!("FAIL bench: {why}");
                    ExitCode::FAILURE
                }
            };
        }
        "" | "-h" | "--help" => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
        name => match CI.iter().find(|(n, _)| *n == name) {
            Some(s) => vec![s],
            None => {
                eprintln!("unknown task '{name}'\n{USAGE}");
                return ExitCode::from(2);
            }
        },
    };

    let mut summary: Vec<(&str, Outcome)> = Vec::new();
    let mut failed = false;
    for (name, run) in steps {
        eprintln!("==> {name}");
        let outcome = run(&root);
        failed = matches!(outcome, Outcome::Fail(_));
        summary.push((name, outcome));
        if failed {
            break;
        }
    }

    eprintln!("\nsummary:");
    for (name, outcome) in &summary {
        match outcome {
            Outcome::Ok => eprintln!("  ok    {name}"),
            Outcome::Fail(why) => eprintln!("  FAIL  {name}: {why}"),
            Outcome::Skip(why) => eprintln!("  skip  {name}: {why}"),
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn workspace_root() -> PathBuf {
    let here = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    here.parent().map(Path::to_path_buf).unwrap_or(here)
}

fn cargo_bin() -> std::ffi::OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

fn cargo() -> Command {
    Command::new(cargo_bin())
}

fn run(mut cmd: Command, root: &Path) -> Outcome {
    match cmd.current_dir(root).status() {
        Ok(s) if s.success() => Outcome::Ok,
        Ok(s) => Outcome::Fail(format!("exit status {s}")),
        Err(e) => Outcome::Fail(format!("could not start: {e}")),
    }
}

fn fmt(root: &Path) -> Outcome {
    let mut c = cargo();
    c.args(["fmt", "--all", "--", "--check"]);
    run(c, root)
}

fn clippy(root: &Path) -> Outcome {
    let mut c = cargo();
    c.args([
        "clippy",
        "--workspace",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ]);
    run(c, root)
}

fn test(root: &Path) -> Outcome {
    let mut c = cargo();
    c.args(["test", "--workspace", "--quiet"]);
    run(c, root)
}

/// Tests against a real kernel, in a throwaway user + network namespace: no
/// root, nothing reaches the host (crates/hal-linux/tests/netns*.rs,
/// apps/corerouter-daemon/tests/netns.rs).
/// Skips where unprivileged user namespaces are not allowed — unless
/// `COREROUTER_REQUIRE_VRF=1` (the Linux CI job), where a skip would hide
/// the VRF tests, so it fails instead.
fn netns(root: &Path) -> Outcome {
    match netns_run(root) {
        Outcome::Skip(why)
            if std::env::var_os("COREROUTER_REQUIRE_VRF").is_some_and(|v| v == "1") =>
        {
            Outcome::Fail(format!(
                "COREROUTER_REQUIRE_VRF=1 but the netns tests cannot run: {why}"
            ))
        }
        other => other,
    }
}

/// `unshare` arguments for a throwaway user + network namespace (no root).
const UNSHARE: [&str; 4] = ["--user", "--map-root-user", "--net", "--"];

/// Can this user create a link inside a fresh namespace? `Err` says why not.
fn netns_probe() -> Result<(), String> {
    if !cfg!(target_os = "linux") {
        return Err("network namespaces are Linux-only".into());
    }
    match Command::new("unshare")
        .args(UNSHARE)
        .args(["ip", "link", "add", "xtask0", "type", "dummy"])
        .output()
    {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => Err(format!(
            "unshare without root is not allowed here ({}); on Ubuntu: \
             sysctl kernel.apparmor_restrict_unprivileged_userns=0",
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => Err(format!("cannot run unshare: {e}")),
    }
}

fn netns_run(root: &Path) -> Outcome {
    if let Err(why) = netns_probe() {
        return Outcome::Skip(why);
    }
    let cargo = cargo_bin();
    let tests = match netns_tests(root) {
        Ok(t) => t,
        Err(e) => return Outcome::Fail(e),
    };
    // One fresh namespace per test binary: each one's guard requires a
    // namespace holding only `lo`.
    for (package, test) in &tests {
        let mut c = Command::new("unshare");
        // Not `--quiet`: one line per test, so a CI log shows which ones ran.
        c.args(UNSHARE)
            .arg(&cargo)
            .args(["test", "-p", package, "--test", test])
            .env("COREROUTER_NETNS_TESTS", "1");
        if let Outcome::Fail(e) = run(c, root) {
            return Outcome::Fail(format!("{package} {test}: {e}"));
        }
    }
    Outcome::Ok
}

/// Integration tests that need a kernel: every `tests/netns*.rs` of every
/// workspace package, as (package, test), sorted. Found, not listed: a new
/// netns test needs no edit here (the list was a merge-conflict hot spot).
fn netns_tests(root: &Path) -> Result<Vec<(String, String)>, String> {
    let out = cargo()
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cargo metadata: {e}"))?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).into_owned());
    }
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|e| format!("cargo metadata: {e}"))?;
    let mut found = Vec::new();
    let packages = json.get("packages").and_then(serde_json::Value::as_array);
    for p in packages.into_iter().flatten() {
        let name = p.get("name").and_then(serde_json::Value::as_str);
        let manifest = p.get("manifest_path").and_then(serde_json::Value::as_str);
        let (Some(name), Some(manifest)) = (name, manifest) else {
            continue;
        };
        let Some(dir) = Path::new(manifest).parent() else {
            continue;
        };
        let Ok(entries) = std::fs::read_dir(dir.join("tests")) else {
            continue;
        };
        for e in entries.flatten() {
            let file = e.file_name();
            let Some(stem) = file.to_str().and_then(|f| f.strip_suffix(".rs")) else {
                continue;
            };
            if stem.starts_with("netns") && e.path().is_file() {
                found.push((name.to_owned(), stem.to_owned()));
            }
        }
    }
    found.sort();
    Ok(found)
}

fn layers_step(root: &Path) -> Outcome {
    let out = match cargo()
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(root)
        .output()
    {
        Ok(o) if o.status.success() => o.stdout,
        Ok(o) => return Outcome::Fail(String::from_utf8_lossy(&o.stderr).into_owned()),
        Err(e) => return Outcome::Fail(format!("cargo metadata: {e}")),
    };
    let json: serde_json::Value = match serde_json::from_slice(&out) {
        Ok(j) => j,
        Err(e) => return Outcome::Fail(format!("cargo metadata output: {e}")),
    };
    let pkgs = layers::parse_metadata(&json);
    let violations = layers::check(&pkgs);
    for v in &violations {
        eprintln!("  {v}");
    }
    if violations.is_empty() {
        eprintln!("  {} crates, all layer rules hold", pkgs.len());
        Outcome::Ok
    } else {
        Outcome::Fail(format!("{} layer violation(s)", violations.len()))
    }
}

fn agents_sync(root: &Path) -> Outcome {
    let read = |f: &str| std::fs::read(root.join(f)).map_err(|e| format!("{f}: {e}"));
    match (read("AGENTS.md"), read("CLAUDE.md")) {
        (Ok(a), Ok(c)) if a == c => Outcome::Ok,
        (Ok(_), Ok(_)) => {
            Outcome::Fail("AGENTS.md and CLAUDE.md differ; copy one onto the other".into())
        }
        (Err(e), _) | (_, Err(e)) => Outcome::Fail(e),
    }
}

fn wasm(root: &Path) -> Outcome {
    let installed = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .current_dir(root)
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|l| l.trim() == WASM_TARGET)
        })
        .unwrap_or(false);
    if !installed {
        return Outcome::Skip(format!(
            "target not installed: rustup target add {WASM_TARGET}"
        ));
    }
    let mut c = cargo();
    c.args(["check", "--target", WASM_TARGET]);
    for p in WASM_PACKAGES {
        c.args(["-p", p]);
    }
    run(c, root)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netns_tests_are_found_not_listed() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let found = netns_tests(&root).unwrap();
        for want in [
            ("corerouter-hal-linux", "netns"),
            ("corerouter-daemon", "netns_dhcp"),
            ("corerouter-discovery", "netns_local"),
        ] {
            assert!(
                found.iter().any(|(p, t)| p == want.0 && t == want.1),
                "{want:?} missing from {found:?}"
            );
        }
        let mut sorted = found.clone();
        sorted.sort();
        assert_eq!(found, sorted);
        assert!(found.iter().all(|(_, t)| t.starts_with("netns")));
    }
}

//! `cargo xtask <task>` — checks as code. Agents run `cargo xtask ci` before
//! every commit; it stops at the first FAIL and prints an ok/FAIL/skip summary.

mod bench;
mod changes;
mod layers;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const USAGE: &str = "usage: cargo xtask <ci|fmt|clippy|test|bench-check|netns|docs|layers|agents-sync|wasm|bench|docs fold [--help]>";

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
    // docs/changes/*.md (one file per PR) parse and fold into the docs.
    ("docs", changes::check),
    ("layers", layers_step),
    ("agents-sync", agents_sync),
    ("wasm", wasm),
];

/// Left out of `cargo xtask ci --fast`.
const SLOW: &[&str] = &["bench-check", "netns"];

fn main() -> ExitCode {
    let root = workspace_root();
    let task = std::env::args().nth(1).unwrap_or_default();
    let steps: Vec<&Step> = match task.as_str() {
        // `--fast`: the PR gate (deterministic, ~2 min in CI). The steps
        // against a real kernel (`netns`) and `bench-check` run in the full
        // `ci`: locally, on the merge queue's batch and on the main.
        "ci" if std::env::args().nth(2).is_some_and(|a| a == "--fast") => {
            CI.iter().filter(|(name, _)| !SLOW.contains(name)).collect()
        }
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
        "docs" if std::env::args().nth(2).is_some() => {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            return match changes::main(&root, &rest) {
                Outcome::Ok | Outcome::Skip(_) => ExitCode::SUCCESS,
                Outcome::Fail(why) => {
                    eprintln!("FAIL docs: {why}");
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

/// `cargo nextest` when installed (test binaries run in parallel, not one
/// after the other; doctests still go through `cargo test --doc`), else
/// `cargo test`. `COREROUTER_NEXTEST=0` forces `cargo test`.
fn test(root: &Path) -> Outcome {
    if !nextest_available(root) {
        let mut c = cargo();
        c.args(["test", "--workspace", "--quiet"]);
        return run(c, root);
    }
    let mut c = cargo();
    c.args([
        "nextest",
        "run",
        "--workspace",
        "--cargo-quiet",
        "--status-level",
        "fail",
        "--final-status-level",
        "slow",
        // A test that fails and then passes is reported FLAKY and does not
        // fail the run (it gets fixed without stopping the merge queue).
        "--retries",
        "1",
    ]);
    match run(c, root) {
        // `cargo test --doc` costs ~17 s even with no doctest (one rustdoc
        // per crate), so it runs only when some doc comment has Rust code.
        Outcome::Ok if has_doctests(root) => {
            let mut d = cargo();
            d.args(["test", "--workspace", "--doc", "--quiet"]);
            run(d, root)
        }
        other => other,
    }
}

/// Does any `crates/*/src` or `apps/*/src` doc comment open a fenced block
/// that rustdoc runs (no tag, or `rust…` without `ignore`)?
fn has_doctests(root: &Path) -> bool {
    let mut files = Vec::new();
    for top in ["crates", "apps"] {
        let Ok(dirs) = std::fs::read_dir(root.join(top)) else {
            continue;
        };
        for dir in dirs.flatten() {
            collect_rs(&dir.path().join("src"), &mut files);
        }
    }
    files
        .iter()
        .any(|f| std::fs::read_to_string(f).is_ok_and(|text| doc_has_rust_block(&text)))
}

fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_rs(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

fn doc_has_rust_block(text: &str) -> bool {
    let mut open = false;
    for line in text.lines() {
        let l = line.trim_start();
        let Some(doc) = l.strip_prefix("///").or_else(|| l.strip_prefix("//!")) else {
            continue;
        };
        let Some(tag) = doc.trim().strip_prefix("```") else {
            continue;
        };
        if open {
            open = false;
            continue;
        }
        open = true;
        let tag = tag.trim();
        if (tag.is_empty() || tag.starts_with("rust")) && !tag.contains("ignore") {
            return true;
        }
    }
    false
}

fn nextest_available(root: &Path) -> bool {
    if std::env::var_os("COREROUTER_NEXTEST").is_some_and(|v| v == "0") {
        return false;
    }
    cargo()
        .args(["nextest", "--version"])
        .current_dir(root)
        .output()
        .is_ok_and(|o| o.status.success())
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
    let tests = match netns_tests(root) {
        Ok(t) => t,
        Err(e) => return Outcome::Fail(e),
    };
    let bins = match netns_build(root, &tests) {
        Ok(b) => b,
        Err(e) => return Outcome::Fail(e),
    };
    // All binaries at once, one fresh namespace each (each one's guard
    // requires a namespace holding only `lo`): ~3× faster than one after the
    // other (docs/perf.md). Output is printed per binary, not interleaved.
    let running: Vec<_> = bins.iter().map(|b| (b, netns_child(b))).collect();
    let mut failed = Vec::new();
    let mut again = Vec::new();
    for (b, child) in running {
        let name = format!("{} {}", b.package, b.test);
        match child.and_then(std::process::Child::wait_with_output) {
            Ok(out) => {
                // Not quiet: one line per test, so a CI log shows which ran.
                eprintln!("--- {name}");
                eprint!("{}", String::from_utf8_lossy(&out.stdout));
                eprint!("{}", String::from_utf8_lossy(&out.stderr));
                if !out.status.success() {
                    again.push(b);
                }
            }
            Err(e) => failed.push(format!("{name}: could not start: {e}")),
        }
    }
    // A binary that failed runs once more, alone, in a fresh namespace:
    // these tests time real kernel events (DAD, LLDP intervals), and a busy
    // machine made good PRs fail. Passing the second time = flaky, reported
    // (a GitHub annotation in CI) but not failing.
    for b in again {
        let name = format!("{} {}", b.package, b.test);
        eprintln!("--- {name} (again, alone)");
        match netns_child(b).and_then(|c| c.wait_with_output()) {
            Ok(out) if out.status.success() => {
                let note = format!("flaky netns test {name}: failed, then passed alone");
                if std::env::var_os("GITHUB_ACTIONS").is_some() {
                    eprintln!("::warning::{note}");
                } else {
                    eprintln!("warning: {note}");
                }
            }
            Ok(out) => {
                eprint!("{}", String::from_utf8_lossy(&out.stdout));
                eprint!("{}", String::from_utf8_lossy(&out.stderr));
                failed.push(format!("{name}: {}", out.status));
            }
            Err(e) => failed.push(format!("{name}: could not start: {e}")),
        }
    }
    if failed.is_empty() {
        Outcome::Ok
    } else {
        Outcome::Fail(failed.join("; "))
    }
}

/// One netns test binary, started in its own fresh namespace.
fn netns_child(b: &NetnsBin) -> std::io::Result<std::process::Child> {
    Command::new("unshare")
        .args(UNSHARE)
        .arg(&b.exe)
        .current_dir(&b.dir)
        .env("COREROUTER_NETNS_TESTS", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
}

struct NetnsBin {
    package: String,
    test: String,
    exe: PathBuf,
    /// The package directory: where `cargo test` would run the binary.
    dir: PathBuf,
}

/// Build every netns test binary in one `cargo test --no-run` (outside the
/// namespace) and return the executables.
fn netns_build(root: &Path, tests: &[NetnsTest]) -> Result<Vec<NetnsBin>, String> {
    let mut c = cargo();
    c.args([
        "test",
        "--no-run",
        "--message-format=json-render-diagnostics",
    ]);
    for t in tests {
        c.args(["-p", &t.package, "--test", &t.test]);
    }
    let out = c
        .current_dir(root)
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|e| format!("cargo test --no-run: {e}"))?;
    if !out.status.success() {
        return Err(format!("cargo test --no-run: {}", out.status));
    }
    let mut bins = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let Ok(msg) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let target = msg.get("target");
        let is_test = target
            .and_then(|t| t.get("kind"))
            .and_then(serde_json::Value::as_array)
            .is_some_and(|k| k.iter().any(|k| k == "test"));
        let test = target
            .and_then(|t| t.get("name"))
            .and_then(serde_json::Value::as_str);
        let exe = msg.get("executable").and_then(serde_json::Value::as_str);
        let manifest = msg.get("manifest_path").and_then(serde_json::Value::as_str);
        let (true, Some(test), Some(exe), Some(manifest)) = (is_test, test, exe, manifest) else {
            continue;
        };
        let dir = Path::new(manifest)
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_default();
        let Some(t) = tests.iter().find(|t| t.test == test && t.dir == dir) else {
            continue;
        };
        bins.push(NetnsBin {
            package: t.package.clone(),
            test: t.test.clone(),
            exe: PathBuf::from(exe),
            dir,
        });
    }
    if bins.len() != tests.len() {
        return Err(format!(
            "cargo test --no-run built {} of {} netns test binaries",
            bins.len(),
            tests.len()
        ));
    }
    Ok(bins)
}

/// One `tests/netns*.rs` integration test.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct NetnsTest {
    package: String,
    test: String,
    /// The package directory.
    dir: PathBuf,
}

/// Integration tests that need a kernel: every `tests/netns*.rs` of every
/// workspace package, sorted. Found, not listed: a new
/// netns test needs no edit here (the list was a merge-conflict hot spot).
fn netns_tests(root: &Path) -> Result<Vec<NetnsTest>, String> {
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
                found.push(NetnsTest {
                    package: name.to_owned(),
                    test: stem.to_owned(),
                    dir: dir.to_path_buf(),
                });
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
                found
                    .iter()
                    .any(|t| t.package == want.0 && t.test == want.1),
                "{want:?} missing from {found:?}"
            );
        }
        let mut sorted = found.clone();
        sorted.sort();
        assert_eq!(found, sorted);
        assert!(found.iter().all(|t| t.test.starts_with("netns")));
    }
}

#[cfg(test)]
mod doctest_tests {
    use super::doc_has_rust_block;

    #[test]
    fn only_runnable_rust_blocks_count() {
        assert!(!doc_has_rust_block(
            "//! ```text\n//! a\n//! ```\n/// ```sh\n/// x\n/// ```\n"
        ));
        assert!(!doc_has_rust_block("/// ```rust,ignore\n/// x\n/// ```\n"));
        assert!(doc_has_rust_block(
            "//! ```text\n//! a\n//! ```\n/// ```\n/// let x = 1;\n/// ```\n"
        ));
        assert!(doc_has_rust_block("/// ```rust,no_run\n/// x\n/// ```\n"));
        assert!(!doc_has_rust_block("// ```\nfn main() {}\n"));
    }
}

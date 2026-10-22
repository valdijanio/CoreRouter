//! `cargo xtask <task>` — checks as code. Agents run `cargo xtask ci` before
//! every commit; it stops at the first FAIL and prints an ok/FAIL/skip summary.

mod layers;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

const USAGE: &str = "usage: cargo xtask <ci|fmt|clippy|test|netns|layers|agents-sync|wasm>";

/// Crates that must keep compiling for the browser.
const WASM_PACKAGES: &[&str] = &[
    "corerouter-model",
    "corerouter-hal",
    "corerouter-proto-lldp",
    "corerouter-proto-mndp",
    "corerouter-engine",
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

fn cargo() -> Command {
    Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
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

/// hal-linux against a real kernel, in a throwaway user + network namespace:
/// no root, nothing reaches the host (crates/hal-linux/tests/netns.rs).
/// Skips where unprivileged user namespaces are not allowed.
fn netns(root: &Path) -> Outcome {
    if !cfg!(target_os = "linux") {
        return Outcome::Skip("network namespaces are Linux-only".into());
    }
    const UNSHARE: [&str; 4] = ["--user", "--map-root-user", "--net", "--"];
    // Probe: can this user create a link inside a fresh namespace?
    match Command::new("unshare")
        .args(UNSHARE)
        .args(["ip", "link", "add", "xtask0", "type", "dummy"])
        .output()
    {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            return Outcome::Skip(format!(
                "unshare without root is not allowed here ({}); on Ubuntu: \
                 sysctl kernel.apparmor_restrict_unprivileged_userns=0",
                String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
        Err(e) => return Outcome::Skip(format!("cannot run unshare: {e}")),
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    // One fresh namespace per test binary: each one's guard requires a
    // namespace holding only `lo`.
    for test in NETNS_TESTS {
        let mut c = Command::new("unshare");
        c.args(UNSHARE)
            .arg(&cargo)
            .args([
                "test",
                "--quiet",
                "-p",
                "corerouter-hal-linux",
                "--test",
                test,
            ])
            .env("COREROUTER_NETNS_TESTS", "1");
        if let Outcome::Fail(e) = run(c, root) {
            return Outcome::Fail(format!("{test}: {e}"));
        }
    }
    Outcome::Ok
}

/// hal-linux integration tests that need a kernel (`tests/<name>.rs`).
const NETNS_TESTS: &[&str] = &[
    "netns", // G5.2: LLDP over AF_PACKET and MNDP over UDP between veth peers.
    "netns_l2",
];

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

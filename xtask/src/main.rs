//! `cargo xtask <task>` — checks as code. Agents run `cargo xtask ci` before
//! every commit; it stops at the first FAIL and prints an ok/FAIL/skip summary.

mod affected;
mod bench;
mod bng_lab;
mod changes;
mod ebpf;
mod layers;
mod os;
mod oui;
mod package;
mod regressions;
mod slots;
mod slowest;
mod vm_lab;
mod vm_tools;

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::sync::OnceLock;
use std::time::Duration;

const USAGE: &str = "usage: cargo xtask <ci [--affected [--base <ref>]] [--fast] [--only <step>,...] [--no-wait]|fmt|clippy|test|bench-check|netns|xdp-root|docs|ebpf-check|layers|agents-sync|wasm|bench|bng-lab|ebpf|docs fold|vm-lab|os|package gui [--help]>";

/// Crates that must keep compiling for the browser.
const WASM_PACKAGES: &[&str] = &[
    "corerouter-model",
    "corerouter-hal",
    "corerouter-proto-lldp",
    "corerouter-proto-mndp",
    "corerouter-proto-flow",
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
    // G2.5: the XDP object loaded for real, as root (CI runner only).
    ("xdp-root", ebpf::root_test),
    // docs/changes/*.md (one file per PR) parse and fold into the docs.
    ("docs", changes::check),
    // G2.5: prebuilt XDP object up to date with its sources (and rebuilt
    // where the nightly + bpf-linker are installed).
    ("ebpf-check", ebpf::check),
    ("layers", layers_step),
    ("agents-sync", agents_sync),
    ("wasm", wasm),
];

/// Left out of `cargo xtask ci --fast`.
const SLOW: &[&str] = &["bench-check", "netns", "xdp-root"];

/// G0.30: left out of `cargo xtask ci --affected` (the slow layer; the
/// merge queue's batch runs them), unless `--only` names them.
const QUICK_LEAVES_OUT: &[&str] = &["netns", "xdp-root"];

/// G0.29: steps that compile; a run with one of them takes a machine slot
/// (`slots`).
const HEAVY: &[&str] = &[
    "clippy",
    "test",
    "bench-check",
    "netns",
    "xdp-root",
    "ebpf-check",
    "wasm",
];

/// G0.29: the packages `cargo xtask ci --affected` limits the cargo steps
/// to; unset, the whole workspace.
static SCOPE: OnceLock<Vec<affected::Package>> = OnceLock::new();

/// G0.30: the slowest tests of this run's `test` step, printed after the
/// summary (and so at the end of every CI log).
static SLOWEST: OnceLock<String> = OnceLock::new();

/// G0.30: which tests the `test` step runs (`TestLayer::from_env`).
static LAYER: OnceLock<TestLayer> = OnceLock::new();

/// G0.30: the test layers. `Quick` is the gate of a PR and of a session
/// (`--fast`, `--affected`): without the tests named `slow_…` (scale,
/// long fuzz, real waits; `.config/nextest.toml`) and with
/// `PROPTEST_CASES=32`. `Full` runs everything with each property test's
/// own case count: the merge queue's batch and the main. The nightly CI
/// is `Full` with `PROPTEST_CASES` raised (`.github/workflows/nightly.yml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestLayer {
    Quick,
    Full,
}

/// Property-test cases in the quick layer: proptest's 256 (or a test's
/// own count) are for the batch; a session's gate checks the shape.
const QUICK_PROPTEST_CASES: &str = "32";

impl TestLayer {
    /// `COREROUTER_TEST_LAYER=quick|full` when set (the GitHub PR job sets
    /// `quick`), else `Quick` for the fast gates and `Full` for the rest.
    fn from_env(fast_gate: bool) -> Result<Self, String> {
        Self::parse(
            std::env::var("COREROUTER_TEST_LAYER").ok().as_deref(),
            fast_gate,
        )
    }

    fn parse(var: Option<&str>, fast_gate: bool) -> Result<Self, String> {
        match var.map(str::trim) {
            None | Some("") => Ok(Self::default_for(fast_gate)),
            Some("quick") => Ok(Self::Quick),
            Some("full") => Ok(Self::Full),
            Some(other) => {
                let shown: String = other.chars().take(20).collect();
                Err(format!(
                    "COREROUTER_TEST_LAYER: expected quick or full, got '{shown}'"
                ))
            }
        }
    }

    fn default_for(fast_gate: bool) -> Self {
        if fast_gate { Self::Quick } else { Self::Full }
    }

    /// The nextest profile (`.config/nextest.toml`).
    fn profile(self) -> &'static str {
        match self {
            Self::Quick => "quick",
            Self::Full => "default",
        }
    }
}

/// `--workspace`, or `-p` for each package of the `--affected` scope that
/// `keep` accepts. `None` when the scope has none of them (skip the step).
fn package_args(keep: impl Fn(&affected::Package) -> bool) -> Option<Vec<String>> {
    let Some(scope) = SCOPE.get() else {
        return Some(vec!["--workspace".into()]);
    };
    let args: Vec<String> = scope
        .iter()
        .filter(|p| keep(p))
        .flat_map(|p| ["-p".to_owned(), p.name.clone()])
        .collect();
    (!args.is_empty()).then_some(args)
}

/// Did the diff change `package` itself (always true without a scope)?
fn changed_in_scope(package: &str) -> bool {
    SCOPE
        .get()
        .is_none_or(|s| s.iter().any(|p| p.name == package && p.changed))
}

/// Is `package` in the `--affected` scope (always, without one)?
fn in_scope(package: &str) -> bool {
    SCOPE
        .get()
        .is_none_or(|s| s.iter().any(|p| p.name == package))
}

fn main() -> ExitCode {
    let root = workspace_root();
    let mut held_slot: Option<slots::Slot> = None;
    let task = std::env::args().nth(1).unwrap_or_default();
    let steps: Vec<&Step> = match task.as_str() {
        // `--fast`: the PR gate (deterministic, ~2 min in CI). The steps
        // against a real kernel (`netns`) and `bench-check` run in the full
        // `ci`: locally, on the merge queue's batch and on the main.
        // `--only a,b`: those steps, in `CI` order (the GitHub workflow runs
        // the full gate as parallel jobs, one group of steps each).
        "ci" => {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            let args = match ci_args(&rest) {
                Ok(a) => a,
                Err(why) => {
                    eprintln!(
                        "{why}\nusage: cargo xtask ci [--affected [--base <ref>]] [--fast] \
                         [--only <step>[,<step>...]] [--no-wait]"
                    );
                    return ExitCode::from(2);
                }
            };
            let layer = match TestLayer::from_env(args.affected || args.fast) {
                Ok(l) => l,
                Err(why) => {
                    eprintln!("FAIL {why}");
                    return ExitCode::from(2);
                }
            };
            let _ = LAYER.set(layer);
            let steps = if args.affected {
                match affected_steps(&root, &args.base, args.steps, args.only) {
                    Ok(s) => s,
                    Err(why) => {
                        eprintln!("FAIL --affected: {why}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                args.steps
            };
            // G0.29: a machine slot for runs that compile (not in GitHub
            // Actions: one job per runner). Held until `main` returns.
            let heavy = steps.iter().any(|(n, _)| HEAVY.contains(n));
            if heavy && std::env::var_os("GITHUB_ACTIONS").is_none() {
                match slots::acquire(
                    &slots::dir(),
                    slots::count(),
                    args.wait,
                    Duration::from_secs(5),
                ) {
                    Ok(slot) => held_slot = slot,
                    Err(e) => eprintln!("warning: no CI slot: {e}"),
                }
                let target = std::env::var_os("CARGO_TARGET_DIR")
                    .map_or_else(|| root.clone(), PathBuf::from);
                let probe = if target.exists() {
                    target
                } else {
                    root.clone()
                };
                if let Err(e) = slots::wait_for_disk(
                    &probe,
                    slots::min_free_gb(),
                    args.wait,
                    Duration::from_secs(20 * 60),
                ) {
                    eprintln!("FAIL disk: {e}");
                    return ExitCode::FAILURE;
                }
            }
            steps
        }
        "ebpf" => {
            return match ebpf::refresh(&root) {
                Outcome::Ok | Outcome::Skip(_) => ExitCode::SUCCESS,
                Outcome::Fail(why) => {
                    eprintln!("FAIL ebpf: {why}");
                    ExitCode::FAILURE
                }
            };
        }
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
        // G4.3g: BNG Blaster against the daemon (by hand; `--root` asks
        // for sudo).
        "bng-lab" => {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            return match bng_lab::main(&root, &rest) {
                Outcome::Ok => ExitCode::SUCCESS,
                Outcome::Skip(why) => {
                    eprintln!("skip: {why}");
                    ExitCode::SUCCESS
                }
                Outcome::Fail(why) => {
                    eprintln!("FAIL bng-lab: {why}");
                    ExitCode::FAILURE
                }
            };
        }
        // G0.26: the VM lab where agents are root (docs/vm-lab.md).
        "vm-lab" => {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            return match vm_lab::main(&root, &rest) {
                Outcome::Ok | Outcome::Skip(_) => ExitCode::SUCCESS,
                Outcome::Fail(why) => {
                    eprintln!("FAIL vm-lab: {why}");
                    ExitCode::FAILURE
                }
            };
        }
        // G1.27d: the built-in vendor table from the IEEE listing.
        "oui" => {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            return match oui::main(&root, &rest) {
                Outcome::Ok | Outcome::Skip(_) => ExitCode::SUCCESS,
                Outcome::Fail(why) => {
                    eprintln!("FAIL oui: {why}");
                    ExitCode::FAILURE
                }
            };
        }
        // G0.28: the GUI + CLI as a .deb (docs/install-gui.md).
        "package" => {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            return match package::main(&root, &rest) {
                Outcome::Ok | Outcome::Skip(_) => ExitCode::SUCCESS,
                Outcome::Fail(why) => {
                    eprintln!("FAIL package: {why}");
                    ExitCode::FAILURE
                }
            };
        }
        // G1.6a: the OS image (docs/os-image.md).
        "os" => {
            let rest: Vec<String> = std::env::args().skip(2).collect();
            return match os::main(&root, &rest) {
                Outcome::Ok | Outcome::Skip(_) => ExitCode::SUCCESS,
                Outcome::Fail(why) => {
                    eprintln!("FAIL os: {why}");
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
    if let Some(report) = SLOWEST.get() {
        eprintln!("\n{report}");
    }
    drop(held_slot);
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// What `cargo xtask ci <args>` was asked.
struct CiArgs {
    steps: Vec<&'static Step>,
    affected: bool,
    base: String,
    /// `false` with `--no-wait`: no waiting for a slot or for disk.
    wait: bool,
    /// `--fast` was asked.
    fast: bool,
    /// `--only` was asked (the steps are the ones named).
    only: bool,
}

fn ci_args(args: &[String]) -> Result<CiArgs, String> {
    let mut rest = Vec::new();
    let mut out = CiArgs {
        steps: Vec::new(),
        affected: false,
        base: "origin/main".into(),
        wait: true,
        fast: false,
        only: false,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--affected" => out.affected = true,
            "--no-wait" => out.wait = false,
            "--base" => {
                out.base = it.next().ok_or("--base needs a git ref")?.clone();
                out.affected = true;
            }
            other => {
                out.fast |= other == "--fast";
                out.only |= other == "--only" || other.starts_with("--only=");
                rest.push(other.to_owned());
            }
        }
    }
    out.steps = ci_steps(&rest)?;
    Ok(out)
}

/// `--affected`: of `steps`, those the diff since `base` needs, with the
/// cargo steps limited to the affected packages (`SCOPE`). G0.30: without
/// `netns` (the slow layer: the batch runs it) unless `--only` names it.
fn affected_steps(
    root: &Path,
    base: &str,
    steps: Vec<&'static Step>,
    only: bool,
) -> Result<Vec<&'static Step>, String> {
    let steps: Vec<&'static Step> = if only {
        steps
    } else {
        steps
            .into_iter()
            .filter(|(n, _)| !QUICK_LEAVES_OUT.contains(n))
            .collect()
    };
    let files = affected::changed_files(root, base)?;
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
    let packages = affected::parse_metadata(&json, root);
    match affected::plan(&files, &packages) {
        affected::Plan::Full(why) => {
            eprintln!("--affected: everything ({why})");
            Ok(steps)
        }
        affected::Plan::Partial(sel) => {
            let changed: Vec<&str> = sel.changed.iter().map(String::as_str).collect();
            eprintln!(
                "--affected: {} file(s) since {base}; changed: {}; with dependents: {} package(s)",
                files.len(),
                if changed.is_empty() {
                    "no package".into()
                } else {
                    changed.join(", ")
                },
                sel.packages.len()
            );
            let scope = packages
                .into_iter()
                .filter(|p| sel.packages.contains(&p.name))
                .map(|mut p| {
                    p.changed = sel.changed.contains(&p.name);
                    p
                })
                .collect();
            let _ = SCOPE.set(scope);
            let kept: Vec<&'static Step> = steps
                .into_iter()
                .filter(|(n, _)| sel.steps.contains(n))
                .collect();
            let names: Vec<&str> = kept.iter().map(|(n, _)| *n).collect();
            eprintln!(
                "--affected: steps {}",
                if names.is_empty() {
                    "none".into()
                } else {
                    names.join(", ")
                }
            );
            Ok(kept)
        }
    }
}

/// The steps `cargo xtask ci <args>` runs: all, `--fast` (without `SLOW`)
/// or `--only <step>[,<step>...]` (in `CI` order; `--fast` then drops the
/// slow ones).
fn ci_steps(args: &[String]) -> Result<Vec<&'static Step>, String> {
    let mut fast = false;
    let mut only: Option<Vec<String>> = None;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let list = match a.as_str() {
            "--fast" => {
                fast = true;
                continue;
            }
            "--only" => it.next().ok_or("--only needs a list of steps")?.as_str(),
            other => match other.strip_prefix("--only=") {
                Some(list) => list,
                None => return Err(format!("unknown argument '{other}'")),
            },
        };
        let names: Vec<String> = list
            .split(',')
            .map(|n| n.trim().to_owned())
            .filter(|n| !n.is_empty())
            .collect();
        if let Some(bad) = names.iter().find(|n| !CI.iter().any(|(c, _)| c == n)) {
            let known: Vec<&str> = CI.iter().map(|(c, _)| *c).collect();
            return Err(format!(
                "unknown step '{bad}' (steps: {})",
                known.join(", ")
            ));
        }
        if names.is_empty() {
            return Err("--only needs a list of steps".into());
        }
        only.get_or_insert_with(Vec::new).extend(names);
    }
    Ok(CI
        .iter()
        .filter(|(name, _)| only.as_ref().is_none_or(|o| o.iter().any(|n| n == name)))
        .filter(|(name, _)| !fast || !SLOW.contains(name))
        .collect())
}

/// The workspace this run is for: the nearest directory, from the current
/// one up, whose `Cargo.toml` has `[workspace]`. Not `CARGO_MANIFEST_DIR`,
/// which is fixed at build time: worktrees sharing a target directory reused
/// an xtask built in another (deleted) worktree and ran there.
fn workspace_root() -> PathBuf {
    let built = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fallback = built.parent().map(Path::to_path_buf).unwrap_or(built);
    let Ok(mut dir) = std::env::current_dir() else {
        return fallback;
    };
    loop {
        let manifest = dir.join("Cargo.toml");
        if std::fs::read_to_string(&manifest).is_ok_and(|t| t.contains("[workspace]")) {
            return dir;
        }
        if !dir.pop() {
            return fallback;
        }
    }
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
    let Some(pkgs) = package_args(|_| true) else {
        return Outcome::Skip("no package in scope".into());
    };
    let missing = it_mods_missing(root);
    if !missing.is_empty() {
        return Outcome::Fail(format!(
            "not declared in tests/it/main.rs, so never compiled: {}",
            missing.join(", ")
        ));
    }
    let mut c = cargo();
    c.arg("fmt");
    if SCOPE.get().is_none() {
        c.arg("--all");
    } else {
        c.args(pkgs);
    }
    c.args(["--", "--check"]);
    run(c, root)
}

/// G0.29: each crate's integration tests are one binary, `tests/it/main.rs`
/// with a `mod` per file. A file left out of that list would never compile
/// or run, silently: every `tests/it/<name>.rs` (and `<name>/mod.rs`) needs
/// its `mod <name>;`.
fn it_mods_missing(root: &Path) -> Vec<String> {
    let mut missing = Vec::new();
    for top in ["crates", "apps"] {
        let Ok(dirs) = std::fs::read_dir(root.join(top)) else {
            continue;
        };
        let mut dirs: Vec<PathBuf> = dirs.flatten().map(|d| d.path()).collect();
        dirs.sort();
        for dir in dirs {
            let it = dir.join("tests/it");
            let Ok(main) = std::fs::read_to_string(it.join("main.rs")) else {
                continue;
            };
            let declared = it_mod_names(&main);
            let Ok(entries) = std::fs::read_dir(&it) else {
                continue;
            };
            let mut names: Vec<String> = entries
                .flatten()
                .filter_map(|e| {
                    let p = e.path();
                    let file = e.file_name().into_string().ok()?;
                    if p.is_dir() {
                        p.join("mod.rs").is_file().then_some(file)
                    } else {
                        file.strip_suffix(".rs").map(str::to_owned)
                    }
                })
                .filter(|n| n != "main")
                .collect();
            names.sort();
            let shown = it.strip_prefix(root).unwrap_or(&it).display().to_string();
            missing.extend(
                names
                    .into_iter()
                    .filter(|n| !declared.contains(n))
                    .map(|n| format!("{shown}/{n}")),
            );
        }
    }
    missing
}

/// The `mod <name>;` declarations of a `tests/it/main.rs`.
fn it_mod_names(main: &str) -> Vec<String> {
    main.lines()
        .filter_map(|l| {
            let l = l.trim().strip_prefix("pub ").unwrap_or(l.trim());
            l.strip_prefix("mod ")?
                .strip_suffix(';')
                .map(|n| n.trim().to_owned())
        })
        .collect()
}

fn clippy(root: &Path) -> Outcome {
    let Some(pkgs) = package_args(|_| true) else {
        return Outcome::Skip("no package in scope".into());
    };
    let mut c = cargo();
    c.arg("clippy")
        .args(pkgs)
        .args(["--all-targets", "--", "-D", "warnings"]);
    run(c, root)
}

/// `cargo nextest` when installed (test binaries run in parallel, not one
/// after the other; doctests still go through `cargo test --doc`), else
/// `cargo test`. `COREROUTER_NEXTEST=0` forces `cargo test`.
///
/// With `COREROUTER_CI_PARTITION=i/n` (the CI's test shards), nextest runs
/// part i of the tests (`--partition hash:i/n`: a test stays in its part
/// when others are added; `.config/nextest.toml` starts the slow ones
/// first) and only part 1 the
/// doctests; `cargo test` cannot split, so part 1 runs everything.
fn test(root: &Path) -> Outcome {
    let part = match partition() {
        Ok(p) => p,
        Err(e) => return Outcome::Fail(e),
    };
    let first = part.is_none_or(|(i, _)| i == 1);
    let Some(pkgs) = package_args(|_| true) else {
        return Outcome::Skip("no package in scope".into());
    };
    let orphans = regressions::orphans(root);
    if !orphans.is_empty() {
        return Outcome::Fail(format!(
            "proptest regressions no test reads any more (moved or renamed test file? move \
             them next to its new path): {}",
            orphans.join(", ")
        ));
    }
    let layer = LAYER.get().copied().unwrap_or(TestLayer::Full);
    eprintln!(
        "test layer: {}",
        match layer {
            TestLayer::Quick => format!(
                "quick (no slow_ tests, PROPTEST_CASES={}; the batch runs them all)",
                quick_proptest_cases()
            ),
            TestLayer::Full => "full".into(),
        }
    );
    if !nextest_available(root) {
        if !first {
            return Outcome::Skip("no cargo-nextest to split the tests: part 1 runs them".into());
        }
        let mut c = cargo();
        c.arg("test").args(&pkgs).arg("--quiet");
        if layer == TestLayer::Quick {
            c.env("PROPTEST_CASES", quick_proptest_cases());
            c.args(["--", "--skip", "::slow_"]);
        }
        return run(c, root);
    }
    let mut c = cargo();
    if layer == TestLayer::Quick {
        c.env("PROPTEST_CASES", quick_proptest_cases());
    }
    c.args(["nextest", "run", "--profile", layer.profile()])
        .args(&pkgs)
        .args([
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
    if let Some((i, n)) = part {
        c.args(["--partition", &format!("hash:{i}/{n}")]);
    }
    // G0.30: the JUnit report of this run only (none left from an earlier one).
    let junit = slowest::junit_path(root, layer.profile());
    let _ = std::fs::remove_file(&junit);
    let mut outcome = run(c, root);
    if let Ok(xml) = std::fs::read_to_string(&junit) {
        let tests = slowest::parse_junit(&xml);
        let _ = SLOWEST.set(slowest::report(&tests, 20));
        if layer == TestLayer::Quick
            && let Outcome::Ok = outcome
        {
            outcome = budget(&tests);
        }
    }
    match outcome {
        // `cargo test --doc` costs ~17 s even with no doctest (one rustdoc
        // per crate), so it runs only when some doc comment has Rust code.
        Outcome::Ok if first && has_doctests(root) => {
            let mut d = cargo();
            d.arg("test").args(&pkgs).args(["--doc", "--quiet"]);
            run(d, root)
        }
        other => other,
    }
}

/// G0.30: the quick layer's time budget. A test outside the slow layer over
/// the ceiling (5 s) fails the PR's test job in GitHub Actions and is a
/// warning locally (a busy machine slows everything); over 1 s, the tests
/// of the packages this diff changed are listed as a warning.
fn budget(tests: &[slowest::TestTime]) -> Outcome {
    let ceiling = std::env::var("COREROUTER_TEST_CEILING_SECS")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|v| *v > 0.0)
        .unwrap_or(slowest::CEILING_SECS);
    let changed: Option<Vec<String>> = SCOPE.get().map(|s| {
        s.iter()
            .filter(|p| p.changed)
            .map(|p| p.name.clone())
            .collect()
    });
    let warn = slowest::over(tests, slowest::WARN_SECS, changed.as_deref());
    if changed.is_some() && !warn.is_empty() {
        eprintln!(
            "warning: {} test(s) of the changed packages over {} s: simulate the clock or \
             name them slow_… (CLAUDE.md, \"Orçamento de testes\")\n{}",
            warn.len(),
            slowest::WARN_SECS,
            slowest::lines(&warn)
        );
    }
    let over = slowest::over(tests, ceiling, None);
    if over.is_empty() {
        return Outcome::Ok;
    }
    let what = format!(
        "{} test(s) of the quick layer over the {ceiling} s ceiling: simulate the clock or name \
         them slow_… (CLAUDE.md, \"Orçamento de testes\")\n{}",
        over.len(),
        slowest::lines(&over)
    );
    if std::env::var_os("GITHUB_ACTIONS").is_some() {
        Outcome::Fail(what)
    } else {
        eprintln!("warning: {what}");
        Outcome::Ok
    }
}

/// `PROPTEST_CASES` of the quick layer: the caller's when set (a session
/// can ask for more), else `QUICK_PROPTEST_CASES`.
fn quick_proptest_cases() -> String {
    std::env::var("PROPTEST_CASES")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| QUICK_PROPTEST_CASES.to_owned())
}

/// `COREROUTER_CI_PARTITION=i/n` (1 ≤ i ≤ n ≤ 16): this CI job runs part i
/// of n of the steps that split (`test`, `xdp-root`); unset, all of it.
fn partition() -> Result<Option<(usize, usize)>, String> {
    match std::env::var("COREROUTER_CI_PARTITION") {
        Ok(v) if !v.trim().is_empty() => parse_partition(v.trim()).map(Some),
        _ => Ok(None),
    }
}

fn parse_partition(v: &str) -> Result<(usize, usize), String> {
    let bad = || {
        let shown: String = v.chars().take(20).collect();
        format!("COREROUTER_CI_PARTITION: expected i/n with 1 <= i <= n <= 16, got '{shown}'")
    };
    let (i, n) = v.split_once('/').ok_or_else(bad)?;
    let (i, n) = (
        i.parse::<usize>().map_err(|_| bad())?,
        n.parse::<usize>().map_err(|_| bad())?,
    );
    if i == 0 || i > n || n > 16 {
        return Err(bad());
    }
    Ok((i, n))
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
    let tests: Vec<NetnsTest> = match netns_tests(root) {
        Ok(t) => t
            .into_iter()
            .filter(|t| changed_in_scope(&t.package))
            .collect(),
        Err(e) => return Outcome::Fail(e),
    };
    if tests.is_empty() {
        return Outcome::Skip("no netns test in scope".into());
    }
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
    let pkgs: Vec<&&str> = WASM_PACKAGES.iter().filter(|p| in_scope(p)).collect();
    if pkgs.is_empty() {
        return Outcome::Skip("no wasm package in scope".into());
    }
    let mut c = cargo();
    c.args(["check", "--target", WASM_TARGET]);
    for p in pkgs {
        c.args(["-p", p]);
    }
    run(c, root)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(args: &[&str]) -> Result<Vec<&'static str>, String> {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        ci_steps(&args).map(|s| s.iter().map(|(n, _)| *n).collect())
    }

    #[test]
    fn ci_steps_all_fast_and_only() {
        assert_eq!(names(&[]).unwrap().len(), CI.len());
        let fast = names(&["--fast"]).unwrap();
        assert!(SLOW.iter().all(|s| !fast.contains(s)));
        assert_eq!(fast.len(), CI.len() - SLOW.len());
        // `CI` order, whatever the order asked.
        assert_eq!(names(&["--only", "wasm,fmt"]).unwrap(), vec!["fmt", "wasm"]);
        assert_eq!(names(&["--only=netns"]).unwrap(), vec!["netns"]);
        assert_eq!(
            names(&["--only", "test", "--only", "bench-check"]).unwrap(),
            vec!["test", "bench-check"]
        );
        assert_eq!(
            names(&["--fast", "--only", "test,netns"]).unwrap(),
            vec!["test"]
        );
        assert!(
            names(&["--only", "tset"])
                .unwrap_err()
                .contains("unknown step 'tset'")
        );
        assert!(names(&["--only"]).is_err());
        assert!(names(&["--only", ","]).is_err());
        assert!(names(&["--quick"]).is_err());
    }

    #[test]
    fn it_mods_are_all_declared() {
        assert_eq!(
            it_mod_names(
                "//! x\n#[path = \"../s/mod.rs\"]\nmod support;\n\nmod a;\npub mod b;\n// mod c;\n"
            ),
            vec!["support", "a", "b"]
        );
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        assert_eq!(it_mods_missing(&root), Vec::<String>::new());
        let tmp = std::env::temp_dir().join(format!("cr-itmods-{}", std::process::id()));
        let it = tmp.join("crates/x/tests/it");
        std::fs::create_dir_all(it.join("helper")).unwrap();
        std::fs::write(it.join("helper/mod.rs"), "").unwrap();
        std::fs::write(it.join("main.rs"), "mod a;\n").unwrap();
        std::fs::write(it.join("a.rs"), "").unwrap();
        std::fs::write(it.join("b.rs"), "").unwrap();
        assert_eq!(
            it_mods_missing(&tmp),
            vec![
                "crates/x/tests/it/b".to_owned(),
                "crates/x/tests/it/helper".to_owned()
            ]
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn the_fast_gates_take_the_quick_layer() {
        assert_eq!(TestLayer::parse(None, true), Ok(TestLayer::Quick));
        assert_eq!(TestLayer::parse(None, false), Ok(TestLayer::Full));
        assert_eq!(TestLayer::parse(Some(" "), true), Ok(TestLayer::Quick));
        assert_eq!(TestLayer::parse(Some("full"), true), Ok(TestLayer::Full));
        assert_eq!(TestLayer::parse(Some("quick"), false), Ok(TestLayer::Quick));
        assert!(TestLayer::parse(Some("slow"), false).is_err());
        assert_eq!(TestLayer::Quick.profile(), "quick");
        assert_eq!(TestLayer::Full.profile(), "default");
        let args: Vec<String> = ["--affected", "--fast"].map(String::from).into();
        let a = ci_args(&args).unwrap();
        assert!(a.affected && a.fast && !a.only);
        let a = ci_args(&["--only=netns".to_owned()]).unwrap();
        assert!(a.only && !a.fast);
    }

    #[test]
    fn partition_parses_i_of_n() {
        assert_eq!(parse_partition("1/2"), Ok((1, 2)));
        assert_eq!(parse_partition("3/3"), Ok((3, 3)));
        for bad in ["0/2", "3/2", "1/17", "1", "a/b", "1/2/3", ""] {
            assert!(parse_partition(bad).is_err(), "{bad}");
        }
    }

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

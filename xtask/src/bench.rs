//! `cargo xtask bench`: the criterion benchmarks of the workspace (G0.9),
//! then one readable summary of what this run measured.
//!
//! ```text
//! cargo xtask bench                         run all, compare with the previous run
//! cargo xtask bench control                 only benchmarks whose id matches `control`
//! cargo xtask bench --quick                 shorter runs (criterion --quick)
//! cargo xtask bench --save-baseline before  keep this run as "before"
//! cargo xtask bench --baseline before       compare with "before", keep it as it is
//! cargo xtask bench --markdown              also print rows for docs/perf.md
//! cargo xtask bench --check                 build and run each benchmark once (no measurement)
//! ```
//!
//! Results live in `<target>/criterion` (criterion's own layout); the
//! summary reads the `new/benchmark.json`, `new/estimates.json` and
//! `change/estimates.json` this run wrote. The netlink/nftables benchmark
//! runs in a throwaway user + network namespace, like `cargo xtask netns`,
//! and is skipped with a warning where that is not allowed. Nothing here
//! fails on a slow number: machines differ (AGENTS.md, "Desempenho").

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use crate::{Outcome, cargo, run};

/// Bench targets named `netns_*` run inside a throwaway network namespace.
const NETNS_PREFIX: &str = "netns_";

/// Set inside the namespace so the netns benchmark agrees to run.
const NETNS_ENV: &str = "COREROUTER_NETNS_BENCH";

const USAGE: &str = "usage: cargo xtask bench [--check] [--quick] [--markdown] \
                     [--save-baseline NAME | --baseline NAME] [FILTER]";

#[derive(Debug, Default, PartialEq, Eq)]
struct Args {
    check: bool,
    markdown: bool,
    /// Passed through to every criterion binary.
    criterion: Vec<String>,
    /// What the "change" column compares with.
    against: String,
}

fn parse_args(args: &[String]) -> Result<Args, String> {
    let mut out = Args {
        against: "previous run".into(),
        ..Args::default()
    };
    let mut it = args.iter();
    let mut filter = false;
    while let Some(a) = it.next() {
        match a.as_str() {
            "--check" => out.check = true,
            "--markdown" => out.markdown = true,
            "--quick" => out.criterion.push(a.clone()),
            "--save-baseline" | "--baseline" => {
                let name = it.next().ok_or(format!("{a} needs a name"))?;
                if name.is_empty()
                    || !name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
                {
                    return Err(format!(
                        "bad baseline name '{name}' (letters, digits, - _ .)"
                    ));
                }
                out.against = format!("baseline '{name}'");
                out.criterion.push(a.clone());
                out.criterion.push(name.clone());
            }
            "-h" | "--help" => return Err(USAGE.into()),
            f if f.starts_with('-') => return Err(format!("unknown option '{f}'\n{USAGE}")),
            f if !filter => {
                filter = true;
                out.criterion.push(f.to_owned());
            }
            f => return Err(format!("only one FILTER, got another: '{f}'\n{USAGE}")),
        }
    }
    if out.check && !out.criterion.is_empty() {
        return Err("--check takes no other option".into());
    }
    Ok(out)
}

pub fn main(root: &Path, args: &[String]) -> Outcome {
    let args = match parse_args(args) {
        Ok(a) => a,
        Err(e) => return Outcome::Fail(e),
    };
    if args.check {
        return check(root);
    }
    let meta = match metadata(root) {
        Ok(m) => m,
        Err(e) => return Outcome::Fail(e),
    };
    let home = meta.target_dir.join("criterion");
    // One build of every bench target, so features unify once (one `cargo
    // bench -p` per crate rebuilt shared dependencies each time).
    eprintln!("==> build (bench profile)");
    let benches = match build(root, &meta) {
        Ok(b) => b,
        Err(e) => return Outcome::Fail(e),
    };
    let started = SystemTime::now();
    let mut failed = Vec::new();
    let mut skipped = Vec::new();
    for b in &benches {
        let label = format!("{} {}", b.package, b.target);
        eprintln!("==> bench {label}");
        let netns = b.target.starts_with(NETNS_PREFIX);
        let probe = if netns { crate::netns_probe() } else { Ok(()) };
        let outcome = match probe {
            Err(why) => Outcome::Skip(why),
            Ok(()) => {
                let mut c = if netns {
                    let mut c = Command::new("unshare");
                    c.args(crate::UNSHARE).arg(&b.exe).env(NETNS_ENV, "1");
                    c
                } else {
                    Command::new(&b.exe)
                };
                // What `cargo bench` passes; criterion measures only with it.
                c.arg("--bench")
                    .args(&args.criterion)
                    .env("CRITERION_HOME", &home);
                run(c, &b.dir)
            }
        };
        match outcome {
            Outcome::Ok => {}
            Outcome::Fail(e) => failed.push(format!("{label}: {e}")),
            Outcome::Skip(why) => {
                eprintln!("warning: skipped {label}: {why}");
                skipped.push(format!("{label}: {why}"));
            }
        }
    }

    let rows = collect(&home, started);
    print_summary(&rows, &args.against);
    for s in &skipped {
        eprintln!("  skipped: {s}");
    }
    if args.markdown {
        print_markdown(&rows);
    }
    if !failed.is_empty() {
        Outcome::Fail(failed.join("; "))
    } else if rows.is_empty() {
        Outcome::Skip("no benchmark matched".into())
    } else {
        Outcome::Ok
    }
}

/// One built bench binary.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Bench {
    package: String,
    target: String,
    exe: PathBuf,
    /// The package directory: `cargo bench` runs a bench from there.
    dir: PathBuf,
}

struct Meta {
    target_dir: PathBuf,
    /// manifest path → package name.
    packages: Vec<(PathBuf, String)>,
}

fn metadata(root: &Path) -> Result<Meta, String> {
    let out = cargo()
        .args(["metadata", "--no-deps", "--format-version", "1"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("cargo metadata: {e}"))?;
    let json: serde_json::Value =
        serde_json::from_slice(&out.stdout).map_err(|e| format!("cargo metadata output: {e}"))?;
    let target_dir = json
        .get("target_directory")
        .and_then(|t| t.as_str())
        .map(PathBuf::from)
        .ok_or("cargo metadata: no target_directory")?;
    let packages = json
        .get("packages")
        .and_then(|p| p.as_array())
        .into_iter()
        .flatten()
        .filter_map(|p| {
            Some((
                PathBuf::from(p.get("manifest_path")?.as_str()?),
                p.get("name")?.as_str()?.to_owned(),
            ))
        })
        .collect();
    Ok(Meta {
        target_dir,
        packages,
    })
}

/// `cargo bench --no-run` of every bench target; the binaries it built.
fn build(root: &Path, meta: &Meta) -> Result<Vec<Bench>, String> {
    let out = cargo()
        .args([
            "bench",
            "--workspace",
            "--bench",
            "*",
            "--no-run",
            "--message-format=json-render-diagnostics",
        ])
        .current_dir(root)
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|e| format!("cargo bench --no-run: {e}"))?;
    if !out.status.success() {
        return Err(format!("cargo bench --no-run: exit status {}", out.status));
    }
    let mut benches = parse_artifacts(&String::from_utf8_lossy(&out.stdout), meta);
    benches.sort_by(|a, b| (&a.package, &a.target).cmp(&(&b.package, &b.target)));
    // The kernel benchmark last: it is the slowest.
    benches.sort_by_key(|b| b.target.starts_with(NETNS_PREFIX));
    Ok(benches)
}

fn parse_artifacts(stdout: &str, meta: &Meta) -> Vec<Bench> {
    stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|m| m.get("reason").and_then(|r| r.as_str()) == Some("compiler-artifact"))
        .filter_map(|m| {
            let target = m.get("target")?;
            let kinds = target.get("kind")?.as_array()?;
            if !kinds.iter().any(|k| k.as_str() == Some("bench")) {
                return None;
            }
            let manifest = PathBuf::from(m.get("manifest_path")?.as_str()?);
            let package = meta
                .packages
                .iter()
                .find(|(p, _)| *p == manifest)
                .map(|(_, n)| n.clone())?;
            Some(Bench {
                package,
                target: target.get("name")?.as_str()?.to_owned(),
                exe: PathBuf::from(m.get("executable")?.as_str()?),
                dir: manifest.parent()?.to_path_buf(),
            })
        })
        .collect()
}

/// Every benchmark built and run once in criterion's test mode (no
/// measurement): they compile and do not panic. The netns one only prints
/// "skipped" without its namespace.
///
/// One `cargo test --no-run` builds them all in the `bench-check` profile
/// (`opt-level = 1` with the debug assertions of a test build), then the
/// binaries run side by side, as many at a time as there are CPUs. In debug
/// and one after the other (`cargo test --bench '*'`) it took 9 min 55 s in
/// CI, almost all of it running big setups (1M routes, 100k sessions)
/// (docs/perf.md).
pub fn check(root: &Path) -> Outcome {
    let meta = match metadata(root) {
        Ok(m) => m,
        Err(e) => return Outcome::Fail(e),
    };
    let out = cargo()
        .args([
            "test",
            "--workspace",
            "--bench",
            "*",
            "--no-run",
            "--profile",
            "bench-check",
            "--message-format=json-render-diagnostics",
        ])
        .current_dir(root)
        .stderr(std::process::Stdio::inherit())
        .output();
    let out = match out {
        Ok(o) if o.status.success() => o,
        Ok(o) => return Outcome::Fail(format!("cargo test --no-run: exit status {}", o.status)),
        Err(e) => return Outcome::Fail(format!("cargo test --no-run: {e}")),
    };
    let mut benches = parse_artifacts(&String::from_utf8_lossy(&out.stdout), &meta);
    benches.sort_by_key(|b| (slow_rank(&b.target), b.package.clone(), b.target.clone()));
    let workers = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(benches.len())
        .max(1);
    let failed = run_parallel(&benches, workers);
    if failed.is_empty() {
        Outcome::Ok
    } else {
        Outcome::Fail(failed.join("; "))
    }
}

/// The slowest bench binaries in check mode, slowest first (**medido**,
/// 2026-10-26): started first, so none of them begins last and holds the
/// step alone.
const SLOW_FIRST: &[&str] = &[
    "config_store",
    "frames",
    "commit",
    "server_storm",
    "pppoe_bng",
    "routes_full",
    "graph",
    "batch_import",
    "cgnat_who_was",
];

fn slow_rank(target: &str) -> usize {
    SLOW_FIRST
        .iter()
        .position(|s| *s == target)
        .unwrap_or(SLOW_FIRST.len())
}

/// Run every binary in criterion's test mode, `workers` at a time; each
/// one's output is printed whole when it ends. The failures, by name.
fn run_parallel(benches: &[Bench], workers: usize) -> Vec<String> {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let next = AtomicUsize::new(0);
    let failed = Mutex::new(Vec::new());
    std::thread::scope(|scope| {
        for i in 0..workers {
            let (next, failed) = (&next, &failed);
            let spawned = std::thread::Builder::new()
                .name(format!("bench-check-{i}"))
                .spawn_scoped(scope, move || {
                    while let Some(b) = benches.get(next.fetch_add(1, Ordering::Relaxed)) {
                        let label = format!("{} {}", b.package, b.target);
                        let started = std::time::Instant::now();
                        let out = Command::new(&b.exe).current_dir(&b.dir).output();
                        let secs = started.elapsed().as_secs_f64();
                        let why = match out {
                            Ok(o) => {
                                eprintln!(
                                    "--- {label} ({secs:.1} s)\n{}{}",
                                    String::from_utf8_lossy(&o.stdout),
                                    String::from_utf8_lossy(&o.stderr)
                                );
                                (!o.status.success()).then(|| format!("{label}: {}", o.status))
                            }
                            Err(e) => Some(format!("{label}: could not start: {e}")),
                        };
                        if let Some(why) = why
                            && let Ok(mut f) = failed.lock()
                        {
                            f.push(why);
                        }
                    }
                });
            if let Err(e) = spawned
                && let Ok(mut f) = failed.lock()
            {
                f.push(format!("could not start a worker thread: {e}"));
            }
        }
    });
    failed.into_inner().unwrap_or_else(|e| e.into_inner())
}

/// One benchmark of this run.
#[derive(Debug, Clone, PartialEq)]
struct Row {
    id: String,
    /// Median time per iteration and its 95% confidence interval, in ns.
    median: f64,
    low: f64,
    high: f64,
    /// Items per iteration (criterion `Throughput::Elements`).
    elements: Option<u64>,
    /// Relative change of the median against the compared baseline.
    change: Option<f64>,
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn fresh(path: &Path, since: SystemTime) -> bool {
    std::fs::metadata(path)
        .and_then(|m| m.modified())
        .is_ok_and(|t| t >= since)
}

fn median_of(estimates: &serde_json::Value) -> Option<(f64, f64, f64)> {
    let m = estimates.get("median")?;
    let ci = m.get("confidence_interval")?;
    Some((
        m.get("point_estimate")?.as_f64()?,
        ci.get("lower_bound")?.as_f64()?,
        ci.get("upper_bound")?.as_f64()?,
    ))
}

/// The benchmarks whose results were written since `since`, by id.
fn collect(home: &Path, since: SystemTime) -> Vec<Row> {
    let mut found = Vec::new();
    walk(home, 0, &mut found);
    let mut rows: Vec<Row> = found
        .into_iter()
        .filter(|new| fresh(&new.join("estimates.json"), since))
        .filter_map(|new| {
            let bench = read_json(&new.join("benchmark.json"))?;
            let (median, low, high) = median_of(&read_json(&new.join("estimates.json"))?)?;
            let elements = bench
                .get("throughput")
                .and_then(|t| t.get("Elements"))
                .and_then(serde_json::Value::as_u64);
            let change_file = new.parent()?.join("change").join("estimates.json");
            let change = if fresh(&change_file, since) {
                read_json(&change_file)
                    .and_then(|c| median_of(&c))
                    .map(|(m, _, _)| m)
            } else {
                None
            };
            Some(Row {
                id: bench.get("full_id")?.as_str()?.to_owned(),
                median,
                low,
                high,
                elements,
                change,
            })
        })
        .collect();
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    rows
}

/// Every `.../new` directory under `dir` (criterion nests ids in folders).
fn walk(dir: &Path, depth: u8, out: &mut Vec<PathBuf>) {
    if depth > 6 {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        if !path.is_dir() {
            continue;
        }
        if path.file_name().is_some_and(|n| n == "new") {
            out.push(path);
        } else if path.file_name().is_some_and(|n| n != "report") {
            walk(&path, depth + 1, out);
        }
    }
}

/// `ns` with three significant digits in the unit that fits.
fn human(ns: f64) -> String {
    let (v, unit) = if ns < 1e3 {
        (ns, "ns")
    } else if ns < 1e6 {
        (ns / 1e3, "µs")
    } else if ns < 1e9 {
        (ns / 1e6, "ms")
    } else {
        (ns / 1e9, "s")
    };
    if v < 10.0 {
        format!("{v:.2} {unit}")
    } else if v < 100.0 {
        format!("{v:.1} {unit}")
    } else {
        format!("{v:.0} {unit}")
    }
}

fn per_item(r: &Row) -> Option<String> {
    let n = r.elements.filter(|n| *n > 1)?;
    Some(human(r.median / n as f64))
}

fn change(r: &Row) -> String {
    r.change
        .map(|c| format!("{:+.1}%", c * 100.0))
        .unwrap_or_else(|| "-".into())
}

fn print_summary(rows: &[Row], against: &str) {
    let width = rows.iter().map(|r| r.id.len()).max().unwrap_or(9).max(9);
    eprintln!("\nbenchmarks ({}):", machine());
    eprintln!(
        "  {:width$}  {:>9}  {:>21}  {:>9}  change vs {against}",
        "benchmark", "median", "95% CI", "per item"
    );
    for r in rows {
        eprintln!(
            "  {:width$}  {:>9}  {:>21}  {:>9}  {}",
            r.id,
            human(r.median),
            format!("[{} .. {}]", human(r.low), human(r.high)),
            per_item(r).unwrap_or_default(),
            change(r),
        );
    }
}

fn print_markdown(rows: &[Row]) {
    println!(
        "\nMáquina: {}; build release (`cargo xtask bench`); {}.\n\n\
         | Benchmark | Mediana | IC 95% | Por item | Tipo |\n|---|---|---|---|---|",
        machine(),
        today()
    );
    for r in rows {
        println!(
            "| `{}` | {} | {}–{} | {} | medido |",
            r.id,
            human(r.median),
            human(r.low),
            human(r.high),
            per_item(r).unwrap_or_else(|| "—".into()),
        );
    }
}

/// CPU model, logical CPUs and kernel of this machine, for the summary and
/// docs/perf.md.
fn machine() -> String {
    let cpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("model name"))
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| v.split_whitespace().collect::<Vec<_>>().join(" "))
        })
        .unwrap_or_else(|| std::env::consts::ARCH.to_owned());
    let cpus = std::thread::available_parallelism().map_or(0, usize::from);
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|k| format!(", Linux {}", k.trim()))
        .unwrap_or_default();
    format!("{cpu}, {cpus} CPUs{kernel}")
}

/// Today's UTC date as YYYY-MM-DD (civil-from-days, H. Hinnant).
fn today() -> String {
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    civil(i64::try_from(secs / 86_400).unwrap_or(0))
}

fn civil(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Result<Args, String> {
        parse_args(&a.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
    }

    #[test]
    fn options_and_filter() {
        let a = args(&["--quick", "--baseline", "before", "control"]).unwrap();
        assert_eq!(a.criterion, ["--quick", "--baseline", "before", "control"]);
        assert_eq!(a.against, "baseline 'before'");
        assert!(args(&["--check"]).unwrap().check);
        assert!(args(&["--check", "--quick"]).is_err());
        assert!(args(&["--baseline"]).is_err());
        assert!(args(&["--baseline", "../x"]).is_err());
        assert!(args(&["a", "b"]).is_err());
        assert!(args(&["--nope"]).is_err());
    }

    #[test]
    fn bench_binaries_from_cargo_messages() {
        let meta = Meta {
            target_dir: PathBuf::from("/t"),
            packages: vec![(
                PathBuf::from("/w/crates/hal/Cargo.toml"),
                "corerouter-hal".into(),
            )],
        };
        let lines = [
            r#"{"reason":"compiler-artifact","manifest_path":"/w/crates/hal/Cargo.toml","target":{"kind":["bench"],"name":"apply"},"executable":"/t/release/deps/apply-1"}"#,
            r#"{"reason":"compiler-artifact","manifest_path":"/w/crates/hal/Cargo.toml","target":{"kind":["lib"],"name":"corerouter_hal"},"executable":null}"#,
            r#"{"reason":"build-finished","success":true}"#,
            "not json",
        ]
        .join("\n");
        let b = parse_artifacts(&lines, &meta);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].package, "corerouter-hal");
        assert_eq!(b[0].target, "apply");
        assert_eq!(b[0].dir, PathBuf::from("/w/crates/hal"));
    }

    #[test]
    fn units_and_dates() {
        assert_eq!(human(18_940.0), "18.9 µs");
        assert_eq!(human(512.0), "512 ns");
        assert_eq!(human(1.5e6), "1.50 ms");
        assert_eq!(civil(0), "1970-01-01");
        assert_eq!(civil(20_748), "2026-10-22");
        assert_eq!(civil(11_016), "2000-02-29");
    }

    #[test]
    fn summary_reads_criterion_files() {
        let dir = std::env::temp_dir().join(format!("xtask-bench-{}", std::process::id()));
        let new = dir.join("g").join("f").join("100").join("new");
        std::fs::create_dir_all(&new).unwrap();
        let since = SystemTime::now() - std::time::Duration::from_secs(5);
        let est = r#"{"median":{"point_estimate":2000000.0,
            "confidence_interval":{"lower_bound":1900000.0,"upper_bound":2100000.0}}}"#;
        std::fs::write(new.join("estimates.json"), est).unwrap();
        std::fs::write(
            new.join("benchmark.json"),
            r#"{"full_id":"g/f/100","throughput":{"Elements":100}}"#,
        )
        .unwrap();
        let rows = collect(&dir, since);
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "g/f/100");
        assert_eq!(per_item(&rows[0]).unwrap(), "20.0 µs");
        assert_eq!(rows[0].change, None);
    }
}

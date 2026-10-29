//! G0.29: `cargo xtask ci --affected`, the local gate limited to what the
//! branch changed.
//!
//! The files changed since the merge base with `origin/main` (committed,
//! staged, unstaged and untracked) map to workspace packages by directory;
//! the packages that depend on those (reverse dependencies, dev and build
//! included) join them. fmt, clippy and test run on that set, bench-check
//! and netns on the changed packages alone; the other steps run only when
//! the diff touches what they check. A change
//! to a workspace-wide file (manifest, lock, toolchain, xtask, build-support)
//! runs everything. The full gate still runs on the merge queue's batch and
//! on the main.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

/// Files and directories whose change can affect every package.
const WORKSPACE_FILES: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "clippy.toml",
    "rustfmt.toml",
    ".rustfmt.toml",
    "rust-toolchain",
    "rust-toolchain.toml",
];
const WORKSPACE_DIRS: &[&str] = &["xtask/", ".cargo/", ".config/", "build-support/"];

/// Paths outside a package that a package reads at build or test time
/// (`include_bytes!`, fixtures under `CARGO_MANIFEST_DIR/../..`).
const READ_BY: &[(&str, &[&str])] = &[
    (
        "fuzz/",
        &[
            "corerouter-engine",
            "corerouter-control",
            "corerouter-mcp",
            "corerouter-proto-radius",
        ],
    ),
    ("docs/analytics.md", &["corerouter-model"]),
    // The XDP object the loader embeds (the crate is outside the workspace).
    ("crates/dataplane-ebpf/", &["corerouter-hal-linux"]),
];

/// One workspace package, as `cargo metadata --no-deps` describes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub name: String,
    /// The package directory relative to the workspace root, with a
    /// trailing `/` (`crates/engine/`).
    pub dir: String,
    /// Workspace packages it depends on (any kind).
    pub deps: Vec<String>,
    pub has_benches: bool,
    /// Has a `tests/netns*.rs` (the `netns` step runs it).
    pub has_netns: bool,
    /// Changed by the diff itself (not only a dependent of a changed one).
    pub changed: bool,
}

/// What `--affected` runs.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// Everything, and why.
    Full(String),
    Partial(Selection),
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Selection {
    /// The changed packages and everything that depends on them.
    pub packages: BTreeSet<String>,
    /// The changed packages alone (for the summary).
    pub changed: BTreeSet<String>,
    /// The `CI` steps to run.
    pub steps: BTreeSet<&'static str>,
}

/// The plan for these changed files (relative to the workspace root).
pub fn plan(files: &[String], packages: &[Package]) -> Plan {
    let mut sel = Selection::default();
    for f in files {
        if WORKSPACE_FILES.contains(&f.as_str()) || WORKSPACE_DIRS.iter().any(|d| f.starts_with(d))
        {
            return Plan::Full(format!("{f} affects the whole workspace"));
        }
        let mut owners: Vec<&str> = READ_BY
            .iter()
            .filter(|(p, _)| f.starts_with(p))
            .flat_map(|(_, pkgs)| pkgs.iter().copied())
            .collect();
        // The innermost package directory holding the file.
        if let Some(p) = packages
            .iter()
            .filter(|p| f.starts_with(&p.dir))
            .max_by_key(|p| p.dir.len())
        {
            owners.push(&p.name);
            if f.ends_with("Cargo.toml") {
                sel.steps.insert("layers");
            }
        } else if owners.is_empty() && (f.starts_with("crates/") || f.starts_with("apps/")) {
            return Plan::Full(format!("{f} is in no workspace package"));
        }
        sel.changed.extend(owners.iter().map(|o| (*o).to_owned()));
        if f.starts_with("docs/") {
            sel.steps.insert("docs");
        }
        if f == "AGENTS.md" || f == "CLAUDE.md" {
            sel.steps.insert("agents-sync");
        }
        if f.starts_with("crates/dataplane-ebpf/") || f.starts_with("crates/dataplane-ebpf-common/")
        {
            sel.steps.insert("ebpf-check");
        }
    }
    sel.packages = dependents(&sel.changed, packages);
    let chosen: Vec<&Package> = packages
        .iter()
        .filter(|p| sel.packages.contains(&p.name))
        .collect();
    if !chosen.is_empty() {
        sel.steps.extend(["fmt", "clippy", "test"]);
    }
    // The slow steps only for the changed packages themselves: a
    // dependent's benches and kernel tests run in the full gate (merge
    // queue, main). Their compile errors still show in clippy.
    let changed: Vec<&&Package> = chosen
        .iter()
        .filter(|p| sel.changed.contains(&p.name))
        .collect();
    if changed.iter().any(|p| p.has_benches) {
        sel.steps.insert("bench-check");
    }
    if changed.iter().any(|p| p.has_netns) {
        sel.steps.insert("netns");
    }
    if chosen
        .iter()
        .any(|p| crate::WASM_PACKAGES.contains(&p.name.as_str()))
    {
        sel.steps.insert("wasm");
    }
    Plan::Partial(sel)
}

/// `changed` plus every package that depends on one of them, directly or
/// not.
fn dependents(changed: &BTreeSet<String>, packages: &[Package]) -> BTreeSet<String> {
    let mut rev: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for p in packages {
        for d in &p.deps {
            rev.entry(d.as_str()).or_default().push(&p.name);
        }
    }
    let mut out: BTreeSet<String> = BTreeSet::new();
    let mut todo: Vec<&str> = changed.iter().map(String::as_str).collect();
    while let Some(n) = todo.pop() {
        if out.insert(n.to_owned()) {
            todo.extend(rev.get(n).into_iter().flatten().copied());
        }
    }
    out
}

/// The workspace packages from `cargo metadata --no-deps` output.
pub fn parse_metadata(json: &serde_json::Value, root: &Path) -> Vec<Package> {
    let all = json.get("packages").and_then(serde_json::Value::as_array);
    let names: BTreeSet<&str> = all
        .into_iter()
        .flatten()
        .filter_map(|p| p.get("name")?.as_str())
        .collect();
    all.into_iter()
        .flatten()
        .filter_map(|p| {
            let name = p.get("name")?.as_str()?;
            let manifest = Path::new(p.get("manifest_path")?.as_str()?);
            let dir = manifest.parent()?.strip_prefix(root).ok()?;
            let deps = p
                .get("dependencies")?
                .as_array()?
                .iter()
                .filter(|d| d.get("path").is_some())
                .filter_map(|d| d.get("name")?.as_str())
                .filter(|d| names.contains(d))
                .map(str::to_owned)
                .collect();
            let targets = p.get("targets").and_then(serde_json::Value::as_array);
            let has_kind = |kind: &str, prefix: &str| {
                targets.into_iter().flatten().any(|t| {
                    let kinds = t.get("kind").and_then(serde_json::Value::as_array);
                    let tname = t.get("name").and_then(serde_json::Value::as_str);
                    kinds.into_iter().flatten().any(|k| k == kind)
                        && tname.is_some_and(|n| n.starts_with(prefix))
                })
            };
            Some(Package {
                name: name.to_owned(),
                dir: format!("{}/", dir.display()),
                deps,
                has_benches: has_kind("bench", ""),
                has_netns: has_kind("test", "netns"),
                changed: false,
            })
        })
        .collect()
}

/// Files changed since the merge base of `HEAD` and `base`, including
/// uncommitted and untracked ones, relative to the workspace root.
pub fn changed_files(root: &Path, base: &str) -> Result<Vec<String>, String> {
    let git = |args: &[&str]| -> Result<String, String> {
        let out = Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .map_err(|e| format!("git: {e}"))?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            let err: String = err.trim().chars().take(200).collect();
            return Err(format!("git {}: {err}", args.join(" ")));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let mb = git(&["merge-base", "HEAD", base])?;
    let mb = mb.trim();
    let mut files: BTreeSet<String> = BTreeSet::new();
    for out in [
        git(&["diff", "--name-only", "--no-renames", mb])?,
        git(&["ls-files", "--others", "--exclude-standard"])?,
    ] {
        files.extend(out.lines().filter(|l| !l.is_empty()).map(str::to_owned));
    }
    Ok(files.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, dir: &str, deps: &[&str]) -> Package {
        Package {
            name: name.into(),
            dir: dir.into(),
            deps: deps.iter().map(|d| (*d).into()).collect(),
            has_benches: false,
            has_netns: false,
            changed: false,
        }
    }

    /// model ← hal ← engine ← ui ← gui; hal ← hal-linux (benches, netns)
    /// ← daemon; engine ← daemon (dev).
    fn workspace() -> Vec<Package> {
        let mut hal_linux = pkg(
            "corerouter-hal-linux",
            "crates/hal-linux/",
            &["corerouter-hal"],
        );
        hal_linux.has_benches = true;
        hal_linux.has_netns = true;
        vec![
            pkg("corerouter-model", "crates/model/", &[]),
            pkg("corerouter-hal", "crates/hal/", &["corerouter-model"]),
            hal_linux,
            pkg("corerouter-engine", "crates/engine/", &["corerouter-hal"]),
            pkg("corerouter-ui", "crates/ui/", &["corerouter-engine"]),
            pkg("corerouter-gui", "apps/corerouter-gui/", &["corerouter-ui"]),
            pkg(
                "corerouter-daemon",
                "apps/corerouter-daemon/",
                &["corerouter-hal-linux", "corerouter-engine"],
            ),
            pkg("corerouter-proto-radius", "crates/proto-radius/", &[]),
            pkg("corerouter-proto-bgp", "crates/proto-bgp/", &[]),
        ]
    }

    fn sel(files: &[&str]) -> Selection {
        let files: Vec<String> = files.iter().map(|f| (*f).into()).collect();
        match plan(&files, &workspace()) {
            Plan::Partial(s) => s,
            Plan::Full(why) => panic!("full: {why}"),
        }
    }

    fn set(v: &[&str]) -> BTreeSet<String> {
        v.iter().map(|s| (*s).into()).collect()
    }

    #[test]
    fn a_leaf_crate_runs_alone_without_wasm_or_netns() {
        let s = sel(&["crates/proto-bgp/src/lib.rs"]);
        assert_eq!(s.packages, set(&["corerouter-proto-bgp"]));
        assert_eq!(
            s.steps.iter().copied().collect::<Vec<_>>(),
            vec!["clippy", "fmt", "test"]
        );
    }

    #[test]
    fn reverse_dependencies_join_and_pull_their_steps() {
        let s = sel(&["crates/hal/src/lib.rs"]);
        assert_eq!(s.changed, set(&["corerouter-hal"]));
        assert_eq!(
            s.packages,
            set(&[
                "corerouter-hal",
                "corerouter-hal-linux",
                "corerouter-engine",
                "corerouter-ui",
                "corerouter-gui",
                "corerouter-daemon",
            ])
        );
        for step in ["fmt", "clippy", "test", "wasm"] {
            assert!(s.steps.contains(step), "{step}");
        }
        // hal-linux's benches and netns tests only when hal-linux changes.
        for step in ["bench-check", "netns", "docs"] {
            assert!(!s.steps.contains(step), "{step}");
        }
        let s = sel(&["crates/hal-linux/src/lib.rs"]);
        assert!(s.steps.contains("bench-check") && s.steps.contains("netns"));
    }

    #[test]
    fn the_innermost_package_owns_the_file() {
        let s = sel(&["apps/corerouter-daemon/tests/netns_x.rs"]);
        assert_eq!(s.packages, set(&["corerouter-daemon"]));
        // The daemon has no netns target in the fake metadata.
        assert!(!s.steps.contains("netns"));
        assert!(!s.steps.contains("wasm"));
    }

    #[test]
    fn non_code_files_pick_only_their_checks() {
        let s = sel(&[
            "docs/changes/G0.29.md",
            "AGENTS.md",
            "CLAUDE.md",
            "scripts/land.sh",
        ]);
        assert!(s.packages.is_empty());
        assert_eq!(
            s.steps.iter().copied().collect::<Vec<_>>(),
            vec!["agents-sync", "docs"]
        );
        assert!(sel(&[]).steps.is_empty());
    }

    #[test]
    fn files_read_from_outside_a_package_select_the_reader() {
        let s = sel(&["fuzz/seeds/radius/x.bin"]);
        assert!(s.changed.contains("corerouter-proto-radius"));
        assert!(s.changed.contains("corerouter-engine"));
        assert!(!s.packages.contains("corerouter-proto-bgp"));
        let s = sel(&["crates/dataplane-ebpf/src/main.rs"]);
        assert!(s.packages.contains("corerouter-hal-linux"));
        assert!(s.steps.contains("ebpf-check"));
    }

    #[test]
    fn a_crate_manifest_runs_layers_a_workspace_file_runs_everything() {
        assert!(sel(&["crates/engine/Cargo.toml"]).steps.contains("layers"));
        let files = workspace();
        for f in [
            "Cargo.lock",
            "Cargo.toml",
            "xtask/src/main.rs",
            ".cargo/config.toml",
            "build-support/root_modules.rs",
            "clippy.toml",
            "crates/brand-new/src/lib.rs",
        ] {
            assert!(
                matches!(plan(&[f.to_owned()], &files), Plan::Full(_)),
                "{f}"
            );
        }
    }

    #[test]
    fn metadata_gives_path_deps_benches_and_netns_targets() {
        let json = serde_json::json!({"packages": [
            {"name": "a", "manifest_path": "/w/crates/a/Cargo.toml",
             "dependencies": [{"name": "b", "path": "/w/crates/b"}, {"name": "serde"}],
             "targets": [{"name": "a", "kind": ["lib"]}, {"name": "netns_x", "kind": ["test"]}]},
            {"name": "b", "manifest_path": "/w/crates/b/Cargo.toml", "dependencies": [],
             "targets": [{"name": "codec", "kind": ["bench"]}]},
        ]});
        let p = parse_metadata(&json, Path::new("/w"));
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].dir, "crates/a/");
        assert_eq!(p[0].deps, vec!["b".to_owned()]);
        assert!(p[0].has_netns && !p[0].has_benches);
        assert!(p[1].has_benches && !p[1].has_netns);
    }
}

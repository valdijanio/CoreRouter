//! Bakes what this build is into the environment (G0.32): the version
//! (`0.1.0` on a release tag, `0.1.0-dev.<commits on HEAD>` otherwise), the
//! git commit, whether the tree had uncommitted changes and the commit time.
//! A crate of its own: a new commit rebuilds only it and the few crates that
//! read it, not the workspace.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// Only `[0-9A-Za-z.-]`, at most 64 octets: a SemVer pre-release or build
/// part, safe in a file name and a tooltip.
fn clean(s: &str) -> Option<String> {
    (!s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-')))
    .then(|| s.to_owned())
}

fn main() {
    let base = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let commit = git(&["rev-parse", "--short=7", "HEAD"]).and_then(|c| clean(&c));
    // A tree with tracked changes: the commit alone does not say what was
    // built. Untracked files (build output, notes) do not count.
    let dirty = git(&["status", "--porcelain", "--untracked-files=no"]).is_some();
    // `COREROUTER_VERSION` wins (a build outside git, e.g. from a tarball);
    // then a `v<base>` tag on HEAD is the release itself; else a dev build
    // numbered by the commits behind it (grows by one per PR on the main).
    let version = match std::env::var("COREROUTER_VERSION")
        .ok()
        .and_then(|v| clean(&v))
    {
        Some(v) => v,
        None => {
            let tag = format!("v{base}");
            let tagged = git(&["tag", "--points-at", "HEAD"])
                .is_some_and(|t| t.lines().any(|l| l.trim() == tag));
            if tagged && !dirty {
                base.clone()
            } else {
                // A shallow clone (the GitHub checkout) does not have the
                // commits to count: say `dev` without a made-up number.
                let shallow =
                    git(&["rev-parse", "--is-shallow-repository"]).is_some_and(|s| s == "true");
                match git(&["rev-list", "--count", "HEAD"]).and_then(|n| n.parse::<u64>().ok()) {
                    Some(n) if !shallow => format!("{base}-dev.{n}"),
                    _ => format!("{base}-dev"),
                }
            }
        }
    };
    let build = match (&commit, dirty) {
        (Some(c), true) => format!("{c}.dirty"),
        (Some(c), false) => c.clone(),
        (None, _) => "unknown".to_owned(),
    };
    let time = git(&["log", "-1", "--format=%ct", "HEAD"])
        .and_then(|t| t.parse::<u64>().ok())
        .unwrap_or(0);
    println!("cargo:rustc-env=COREROUTER_VERSION={version}");
    println!(
        "cargo:rustc-env=COREROUTER_COMMIT={}",
        commit.as_deref().unwrap_or("unknown")
    );
    println!("cargo:rustc-env=COREROUTER_BUILD={build}");
    println!("cargo:rustc-env=COREROUTER_COMMIT_TIME={time}");
    println!("cargo:rerun-if-env-changed=COREROUTER_VERSION");
    // Rebuild when HEAD moves (a checkout, a new commit on the branch, loose
    // or packed), when a tag is added and when the index changes (dirty).
    for path in [
        git(&["rev-parse", "--git-path", "HEAD"]),
        git(&["rev-parse", "--symbolic-full-name", "HEAD"])
            .and_then(|r| git(&["rev-parse", "--git-path", &r])),
        git(&["rev-parse", "--git-path", "packed-refs"]),
        git(&["rev-parse", "--git-path", "refs/tags"]),
        git(&["rev-parse", "--git-path", "index"]),
    ]
    .into_iter()
    .flatten()
    {
        println!("cargo:rerun-if-changed={path}");
    }
}

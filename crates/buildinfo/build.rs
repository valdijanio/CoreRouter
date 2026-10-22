//! Bakes the git commit into `COREROUTER_COMMIT`. A crate of its own: a new
//! commit rebuilds only it and the few crates that read it, not the workspace.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
        .filter(|s| !s.is_empty())
}

fn main() {
    let commit = git(&["rev-parse", "--short=7", "HEAD"]).unwrap_or_else(|| "unknown".into());
    println!("cargo:rustc-env=COREROUTER_COMMIT={commit}");
    // Rebuild when HEAD moves: a checkout (HEAD) or a new commit on the
    // branch (its ref, loose or packed).
    for path in [
        git(&["rev-parse", "--git-path", "HEAD"]),
        git(&["rev-parse", "--symbolic-full-name", "HEAD"])
            .and_then(|r| git(&["rev-parse", "--git-path", &r])),
        git(&["rev-parse", "--git-path", "packed-refs"]),
    ]
    .into_iter()
    .flatten()
    {
        println!("cargo:rerun-if-changed={path}");
    }
}

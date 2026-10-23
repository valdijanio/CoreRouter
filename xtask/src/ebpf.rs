//! G2.5: the XDP programs (`crates/dataplane-ebpf`) build only with the
//! nightly pinned in their `rust-toolchain.toml`, `-Z build-std=core` and
//! `bpf-linker`. The stable workspace never needs that toolchain: hal-linux
//! embeds `prebuilt/corerouter-xdp.o`, and `prebuilt/corerouter-xdp.sources`
//! records the SHA-256 of every source the object was built from.
//!
//! - `cargo xtask ebpf`: build and refresh `prebuilt/` (needs the toolchain).
//! - step `ebpf-check` (in `ci`): the recorded hash must match the sources,
//!   with or without the toolchain (an edit without a rebuild fails here);
//!   with the toolchain, the program is also built.
//! - step `xdp-root` (full `ci` only): load the object for real, as root,
//!   in a throwaway network namespace. Only where `COREROUTER_REQUIRE_XDP=1`
//!   (the CI runner, a disposable VM with passwordless sudo); elsewhere it
//!   skips and prints the command for a human to run.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

use crate::Outcome;

const CRATE: &str = "crates/dataplane-ebpf";
const COMMON: &str = "crates/dataplane-ebpf-common";
const OBJECT: &str = "crates/dataplane-ebpf/prebuilt/corerouter-xdp.o";
const SOURCES: &str = "crates/dataplane-ebpf/prebuilt/corerouter-xdp.sources";
const BIN: &str = "corerouter-xdp";
const TARGET: &str = "bpfel-unknown-none";

/// The nightly of `crates/dataplane-ebpf/rust-toolchain.toml`.
fn toolchain(root: &Path) -> Result<String, String> {
    let file = root.join(CRATE).join("rust-toolchain.toml");
    let text = std::fs::read_to_string(&file).map_err(|e| format!("{}: {e}", file.display()))?;
    text.lines()
        .find_map(|l| l.trim().strip_prefix("channel = "))
        .map(|c| c.trim_matches('"').to_owned())
        .ok_or_else(|| format!("{}: no channel", file.display()))
}

/// Every file the object depends on, sorted: the program crate (not its
/// `prebuilt/`) and the common crate's manifest and sources (not its test
/// helpers).
fn inputs(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for f in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        ".cargo/config.toml",
    ] {
        files.push(root.join(CRATE).join(f));
    }
    files.push(root.join(COMMON).join("Cargo.toml"));
    crate::collect_rs(&root.join(CRATE).join("src"), &mut files);
    crate::collect_rs(&root.join(COMMON).join("src"), &mut files);
    // Test helpers (feature `testing`) never reach the program.
    files.retain(|f| !f.ends_with("src/testing.rs"));
    files.sort();
    files
}

/// SHA-256 over each input's path (relative, `/`-separated) and contents.
fn sources_hash(root: &Path) -> Result<String, String> {
    let mut h = Sha256::new();
    for f in inputs(root) {
        let rel = f.strip_prefix(root).unwrap_or(&f);
        let name = rel.to_string_lossy().replace('\\', "/");
        let body = std::fs::read(&f).map_err(|e| format!("{name}: {e}"))?;
        h.update(name.as_bytes());
        h.update([0]);
        h.update((body.len() as u64).to_le_bytes());
        h.update(&body);
    }
    Ok(hex(&h.finalize()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What `prebuilt/corerouter-xdp.sources` says: `(sources, object)` hashes.
fn recorded(root: &Path) -> Result<(String, String), String> {
    let text = std::fs::read_to_string(root.join(SOURCES))
        .map_err(|e| format!("{SOURCES}: {e} (run `cargo xtask ebpf`)"))?;
    let field = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(k))
            .map(|v| v.trim().to_owned())
            .ok_or_else(|| format!("{SOURCES}: no `{k}` line"))
    };
    Ok((field("sources ")?, field("object ")?))
}

/// Why the eBPF toolchain is not usable here, if it is not.
fn toolchain_missing(root: &Path, nightly: &str) -> Option<String> {
    let rustc = Command::new("rustup")
        .args(["run", nightly, "rustc", "--print", "sysroot"])
        .output();
    let sysroot = match rustc {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_owned(),
        _ => {
            return Some(format!(
                "{nightly} missing (rustup toolchain install {nightly} --profile minimal -c rust-src)"
            ));
        }
    };
    if !Path::new(&sysroot)
        .join("lib/rustlib/src/rust/library/core")
        .is_dir()
    {
        return Some(format!(
            "rust-src missing (rustup component add rust-src --toolchain {nightly})"
        ));
    }
    match Command::new("bpf-linker")
        .arg("--version")
        .current_dir(root)
        .output()
    {
        Ok(o) if o.status.success() => None,
        _ => Some(
            "bpf-linker missing (release tarball or `cargo binstall bpf-linker`, docs/xdp.md)"
                .into(),
        ),
    }
}

/// Build the program; the object's path.
fn build_object(root: &Path, nightly: &str) -> Result<PathBuf, String> {
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .map(|d| if d.is_absolute() { d } else { root.join(d) })
        .unwrap_or_else(|| root.join("target"))
        .join("ebpf");
    // `rustup run` + a clean environment: the workspace's stable cargo
    // (and its RUSTFLAGS) must not leak into the nightly build.
    let status = Command::new("rustup")
        .args(["run", nightly, "cargo", "build", "--release", "--locked"])
        .current_dir(root.join(CRATE))
        .env("CARGO_TARGET_DIR", &target_dir)
        .env_remove("RUSTFLAGS")
        .env_remove("CARGO")
        .env_remove("RUSTC")
        .env_remove("RUSTUP_TOOLCHAIN")
        .env_remove("CARGO_PROFILE_DEV_DEBUG")
        .env_remove("CARGO_PROFILE_RELEASE_DEBUG")
        .status()
        .map_err(|e| format!("cannot start cargo for the eBPF build: {e}"))?;
    if !status.success() {
        return Err(format!("eBPF build failed: {status}"));
    }
    Ok(target_dir.join(TARGET).join("release").join(BIN))
}

/// `cargo xtask ebpf`: build and refresh `prebuilt/`.
pub fn refresh(root: &Path) -> Outcome {
    let nightly = match toolchain(root) {
        Ok(n) => n,
        Err(e) => return Outcome::Fail(e),
    };
    if let Some(why) = toolchain_missing(root, &nightly) {
        return Outcome::Fail(why);
    }
    let built = match build_object(root, &nightly) {
        Ok(p) => p,
        Err(e) => return Outcome::Fail(e),
    };
    let object = match std::fs::read(&built) {
        Ok(b) => b,
        Err(e) => return Outcome::Fail(format!("{}: {e}", built.display())),
    };
    let sources = match sources_hash(root) {
        Ok(h) => h,
        Err(e) => return Outcome::Fail(e),
    };
    let linker = Command::new("bpf-linker")
        .arg("--version")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_default();
    let record = format!(
        "# Written by `cargo xtask ebpf`; `cargo xtask ebpf-check` compares it.\n\
         sources {sources}\nobject {}\ntoolchain {nightly}\nlinker {linker}\n",
        hex(&Sha256::digest(&object))
    );
    if let Err(e) = std::fs::write(root.join(OBJECT), &object)
        .and_then(|()| std::fs::write(root.join(SOURCES), record))
    {
        return Outcome::Fail(format!("writing prebuilt/: {e}"));
    }
    eprintln!("{OBJECT}: {} bytes, sources {sources}", object.len());
    Outcome::Ok
}

/// Step `ebpf-check`.
pub fn check(root: &Path) -> Outcome {
    let (want, object_hash) = match recorded(root) {
        Ok(r) => r,
        Err(e) => return Outcome::Fail(e),
    };
    let have = match sources_hash(root) {
        Ok(h) => h,
        Err(e) => return Outcome::Fail(e),
    };
    if have != want {
        return Outcome::Fail(format!(
            "the XDP sources changed since {OBJECT} was built: run `cargo xtask ebpf` \
             (needs the toolchain, docs/xdp.md) and commit prebuilt/"
        ));
    }
    match std::fs::read(root.join(OBJECT)) {
        Ok(b) if hex(&Sha256::digest(&b)) == object_hash => {}
        Ok(_) => {
            return Outcome::Fail(format!(
                "{OBJECT} is not the object recorded in {SOURCES}: run `cargo xtask ebpf`"
            ));
        }
        Err(e) => return Outcome::Fail(format!("{OBJECT}: {e}")),
    }
    let nightly = match toolchain(root) {
        Ok(n) => n,
        Err(e) => return Outcome::Fail(e),
    };
    if let Some(why) = toolchain_missing(root, &nightly) {
        return Outcome::Skip(format!(
            "prebuilt object matches its sources; not rebuilt: {why}"
        ));
    }
    match build_object(root, &nightly) {
        Ok(_) => Outcome::Ok,
        Err(e) => Outcome::Fail(e),
    }
}

/// Step `xdp-root`: `tests/xdp_root.rs` of hal-linux, as root, in a
/// throwaway named network namespace (veth pair inside it only).
pub fn root_test(root: &Path) -> Outcome {
    let cmd = "cargo test -p corerouter-hal-linux --test xdp_root --no-run, then: \
               sudo ip netns add crxdp && sudo ip netns exec crxdp env COREROUTER_XDP_ROOT=1 <test binary>; \
               sudo ip netns del crxdp";
    if !std::env::var_os("COREROUTER_REQUIRE_XDP").is_some_and(|v| v == "1") {
        return Outcome::Skip(format!(
            "loading XDP needs root; only the CI runner does it (COREROUTER_REQUIRE_XDP=1). By hand: {cmd}"
        ));
    }
    let exe = match test_binary(root) {
        Ok(e) => e,
        Err(e) => return Outcome::Fail(e),
    };
    let ns = "crxdp";
    let sudo = |args: &[&str]| -> Result<std::process::Output, String> {
        Command::new("sudo")
            .arg("-n")
            .args(args)
            .current_dir(root)
            .output()
            .map_err(|e| format!("sudo: {e}"))
    };
    let _ = sudo(&["ip", "netns", "del", ns]);
    match sudo(&["ip", "netns", "add", ns]) {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            return Outcome::Fail(format!(
                "COREROUTER_REQUIRE_XDP=1 but `sudo ip netns add` failed: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
        Err(e) => return Outcome::Fail(e),
    }
    let exe_s = exe.to_string_lossy().into_owned();
    // One test at a time, each with a deadline, output straight to the log:
    // a hang shows which test, and never holds the CI job.
    let mut failed = Vec::new();
    for (test, secs) in XDP_TESTS {
        eprintln!("--- xdp_root {test}");
        let status = Command::new("timeout")
            .args([
                "--kill-after=10",
                &secs.to_string(),
                "sudo",
                "-n",
                "ip",
                "netns",
                "exec",
                ns,
                "env",
                "COREROUTER_XDP_ROOT=1",
                &exe_s,
                test,
                "--exact",
                "--test-threads=1",
                "--nocapture",
            ])
            .current_dir(root)
            .status();
        match status {
            Ok(s) if s.success() => {}
            Ok(s) if s.code() == Some(124) => failed.push(format!("{test}: timed out after {secs} s")),
            Ok(s) => failed.push(format!("{test}: {s}")),
            Err(e) => failed.push(format!("{test}: {e}")),
        }
    }
    let _ = sudo(&["ip", "netns", "del", ns]);
    if failed.is_empty() {
        Outcome::Ok
    } else {
        Outcome::Fail(failed.join("; "))
    }
}

/// The root tests and how long each may take (seconds).
const XDP_TESTS: [(&str, u32); 4] = [
    ("loads_attaches_and_counts", 180),
    ("kernel_and_host_agree", 300),
    ("perf_lpm_cost", 600),
    ("perf_pktgen_veth", 300),
];

fn test_binary(root: &Path) -> Result<PathBuf, String> {
    let out = crate::cargo()
        .args([
            "test",
            "-p",
            "corerouter-hal-linux",
            "--test",
            "xdp_root",
            "--no-run",
            "--message-format=json-render-diagnostics",
        ])
        .current_dir(root)
        .stderr(std::process::Stdio::inherit())
        .output()
        .map_err(|e| format!("cargo test --no-run: {e}"))?;
    if !out.status.success() {
        return Err(format!("cargo test --no-run: {}", out.status));
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .find_map(|m| m.get("executable")?.as_str().map(PathBuf::from))
        .ok_or_else(|| "xdp_root test binary not found".into())
}

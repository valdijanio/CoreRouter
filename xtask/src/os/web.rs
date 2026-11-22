//! G1.6o: the web GUI of the image (`/usr/share/corerouter/web`), built by
//! `os build` with trunk in release mode, as `ip.service www-ssl` serves it.
//!
//! trunk runs two tools of its own: `wasm-bindgen` (the JS glue, generated:
//! nothing hand-written besides `apps/corerouter-gui/index.html`) and
//! `wasm-opt` (binaryen, `-Oz` style size pass of the release build). trunk
//! would download them unpinned; here they come from their official GitHub
//! releases at fixed versions, checked against the sha256 below, kept in
//! `os/dl/web-tools/` and put first in trunk's `PATH`, and trunk runs
//! `--offline --locked`. wasm-bindgen's version must equal the crate's in
//! `Cargo.lock` (checked). The wasm and the JS are kept gzip-compressed.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use crate::vm_lab::{download, sha256_file};

/// A pinned release tarball and the binary inside it.
struct Tool {
    url: &'static str,
    sha256: &'static str,
    /// Top directory of the tarball; the binary is `<top>/<bin>`.
    top: &'static str,
    bin: &'static str,
}

/// binaryen version_133 (WebAssembly/binaryen releases).
const WASM_OPT: Tool = Tool {
    url: "https://github.com/WebAssembly/binaryen/releases/download/version_133/binaryen-version_133-x86_64-linux.tar.gz",
    sha256: "2dc9c7813f5375db93d96ead4b78222fcc3e2677bbb832297af4797782a37489",
    top: "binaryen-version_133",
    bin: "bin/wasm-opt",
};

/// The CLI of the `wasm-bindgen` crate pinned in Cargo.lock.
const WASM_BINDGEN_VERSION: &str = "0.2.129";
const WASM_BINDGEN: Tool = Tool {
    url: "https://github.com/wasm-bindgen/wasm-bindgen/releases/download/0.2.129/wasm-bindgen-0.2.129-x86_64-unknown-linux-musl.tar.gz",
    sha256: "82d12bb940e2d4e72e0d5605387fc1b8ca179044e012b620f0ce4e7440e8320e",
    top: "wasm-bindgen-0.2.129-x86_64-unknown-linux-musl",
    bin: "wasm-bindgen",
};

/// The trunk this was made with (`cargo install --locked trunk --version`).
const TRUNK_MINOR: &str = "trunk 0.22.";

/// Download (once), check and unpack `tool`; the directory holding its binary.
fn fetch(os: &Path, top: &Path, tool: &Tool) -> Result<PathBuf, String> {
    let name = tool.url.rsplit('/').next().unwrap_or("tool.tar.gz");
    let dl = os.join("dl/web-tools");
    std::fs::create_dir_all(&dl).map_err(|e| format!("{}: {e}", dl.display()))?;
    let tarball = dl.join(name);
    if !tarball.exists() {
        eprintln!("   downloading {}", tool.url);
        download(tool.url, &tarball)?;
    }
    let got = sha256_file(&tarball)?;
    if got != tool.sha256 {
        let _ = std::fs::remove_file(&tarball);
        return Err(format!(
            "{name}: sha256 {got}, expected {} (deleted)",
            tool.sha256
        ));
    }
    let unpack = top.join("web-tools");
    let bin = unpack.join(tool.top).join(tool.bin);
    if !bin.is_file() {
        std::fs::create_dir_all(&unpack).map_err(|e| format!("{}: {e}", unpack.display()))?;
        let st = Command::new("tar")
            .arg("-C")
            .arg(&unpack)
            .arg("-xzf")
            .arg(&tarball)
            .status()
            .map_err(|e| format!("tar: {e}"))?;
        if !st.success() || !bin.is_file() {
            return Err(format!("tar -xzf {name}: {st}, no {}", tool.bin));
        }
    }
    bin.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| format!("{}: no parent", bin.display()))
}

/// The `wasm-bindgen` version in Cargo.lock.
fn locked_bindgen(root: &Path) -> Result<String, String> {
    let lock = std::fs::read_to_string(root.join("Cargo.lock")).map_err(|e| e.to_string())?;
    let mut lines = lock.lines();
    while let Some(l) = lines.next() {
        if l == "name = \"wasm-bindgen\"" {
            return lines
                .next()
                .and_then(|v| v.strip_prefix("version = \""))
                .and_then(|v| v.strip_suffix('"'))
                .map(str::to_owned)
                .ok_or_else(|| "Cargo.lock: wasm-bindgen without a version".into());
        }
    }
    Err("Cargo.lock has no wasm-bindgen".into())
}

/// Build the GUI into `<out>/web` (index.html, the JS glue, the .wasm);
/// the directory, for `COREROUTER_WEB_DIR` of `corerouter.mk`.
pub(super) fn build(root: &Path, top: &Path, cargo_target: &Path) -> Result<PathBuf, String> {
    let os = root.join("os");
    let locked = locked_bindgen(root)?;
    if locked != WASM_BINDGEN_VERSION {
        return Err(format!(
            "Cargo.lock has wasm-bindgen {locked}, xtask/src/os/web.rs pins the CLI \
             {WASM_BINDGEN_VERSION}: update WASM_BINDGEN (url and sha256 of its release)"
        ));
    }
    let trunk = Command::new("trunk")
        .arg("--version")
        .output()
        .map_err(|e| format!("trunk: {e} (cargo install --locked trunk --version 0.22.0)"))?;
    let version = String::from_utf8_lossy(&trunk.stdout).trim().to_owned();
    if !version.starts_with(TRUNK_MINOR) {
        return Err(format!(
            "'{version}': the image is built with {TRUNK_MINOR}x \
             (cargo install --locked trunk --version 0.22.0)"
        ));
    }
    let tools = [fetch(&os, top, &WASM_OPT)?, fetch(&os, top, &WASM_BINDGEN)?];
    let path = std::env::var_os("PATH").unwrap_or_default();
    let path = std::env::join_paths(tools.iter().cloned().chain(std::env::split_paths(&path)))
        .map_err(|e| format!("PATH: {e}"))?;
    let dist = top.join("web");
    let started = Instant::now();
    let mut cmd = Command::new("trunk");
    cmd.current_dir(root.join("apps/corerouter-gui"))
        .args(["build", "--release", "--offline", "--locked", "--dist"])
        .arg(&dist)
        .env("PATH", path)
        .env("CARGO_TARGET_DIR", cargo_target)
        // No absolute path of this machine in the .wasm (panic messages).
        .env(
            "CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUSTFLAGS",
            format!(
                "--remap-path-prefix={}=/corerouter --remap-path-prefix={}=/home",
                root.display(),
                std::env::var("HOME").unwrap_or_default()
            ),
        );
    for var in [
        "CARGO_MANIFEST_DIR",
        "CARGO_PKG_NAME",
        "RUSTFLAGS",
        "CARGO_BUILD_TARGET",
    ] {
        cmd.env_remove(var);
    }
    let st = cmd.status().map_err(|e| format!("trunk: {e}"))?;
    if !st.success() {
        return Err(format!("trunk build --release: {st}"));
    }
    if !dist.join("index.html").is_file() {
        return Err(format!("{}: trunk made no index.html", dist.display()));
    }
    gzip_copies(&dist)?;
    eprintln!(
        "   web GUI ({}) — {:.1} s",
        sizes(&dist)?,
        started.elapsed().as_secs_f64()
    );
    Ok(dist)
}

/// The wasm and the JS glue are kept only as `<file>.gz`, served to
/// browsers that take gzip (`control::ws`, like nginx's `gzip_static`): 32 →
/// 11 MiB on the wire, and only 1.6 MiB more in the squashfs than the plain
/// wasm (zstd compresses that to ~10 MiB; both would cost 21 MiB, **medido**).
/// `-n`: no name or time inside, the same bytes every build.
fn gzip_copies(dist: &Path) -> Result<(), String> {
    for e in std::fs::read_dir(dist).map_err(|e| format!("{}: {e}", dist.display()))? {
        let p = e.map_err(|e| e.to_string())?.path();
        let ext = p.extension().and_then(|x| x.to_str());
        if !matches!(ext, Some("wasm" | "js")) {
            continue;
        }
        let st = Command::new("gzip")
            .args(["-9", "-n", "-f"])
            .arg(&p)
            .status()
            .map_err(|e| format!("gzip: {e}"))?;
        if !st.success() {
            return Err(format!("gzip {}: {st}", p.display()));
        }
    }
    Ok(())
}

/// "N files, X MiB" of what goes into the image.
fn sizes(dist: &Path) -> Result<String, String> {
    let mut n = 0u32;
    let mut bytes = 0u64;
    for e in std::fs::read_dir(dist).map_err(|e| format!("{}: {e}", dist.display()))? {
        let e = e.map_err(|e| e.to_string())?;
        if e.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let m = e.metadata().map_err(|e| e.to_string())?;
        if m.is_file() {
            n += 1;
            bytes += m.len();
        }
    }
    Ok(format!("{n} files, {:.1} MiB", bytes as f64 / 1048576.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pinned_wasm_bindgen_is_the_locked_one() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        assert_eq!(locked_bindgen(&root).unwrap(), WASM_BINDGEN_VERSION);
        assert!(WASM_BINDGEN.url.contains(WASM_BINDGEN_VERSION));
        for t in [&WASM_OPT, &WASM_BINDGEN] {
            assert_eq!(t.sha256.len(), 64);
            assert!(t.url.starts_with("https://github.com/"));
        }
    }
}

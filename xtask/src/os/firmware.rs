//! G1.6j: the firmware of the image's drivers (`docs/os-image.md`, "Firmware
//! das placas"): the network cards' and, since G1.6zd, the screen's (`i915`). `os/package/corerouter-firmware/firmware.lock` pins a tag of
//! `linux-firmware` and the SHA-256 of each file; the build downloads only
//! those files (the whole tarball is over 600 MB for what is a few MB here)
//! into `os/dl/`, checks them and stages them, with their licenses, for the
//! package to install.
//!
//! `cargo xtask os firmware-lock --tag T` writes the lock from what the
//! built kernel's drivers of [`DRIVERS`] declare (`firmware=` in their modinfo,
//! the way VyOS picks its set) and from `WHENCE`: a file whose entry states no
//! permission to redistribute does not enter, it is listed as `skip`.
//! After each build, [`verify`] fails if a driver declares a file that is
//! neither in the image nor in a `skip` line.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use crate::vm_lab::{download, sha256_file};

pub(super) const LOCK: &str = "package/corerouter-firmware/firmware.lock";
const REPO: &str = "https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git";
/// The drivers whose firmware the image carries, by their directory in
/// `lib/modules`: the ports' and the screen's.
const DRIVERS: [&str; 2] = ["kernel/drivers/net/", "kernel/drivers/gpu/drm/"];
/// Where the licenses go in the image.
const LICENSE_DIR: &str = "usr/share/licenses/firmware";
/// Files downloaded at the same time (kernel.org answers small files fast;
/// one by one, 100 of them take most of a minute).
const FETCHERS: usize = 8;
/// Far more than the set can ever have.
const MAX_LOCK_LINES: usize = 20_000;

#[derive(Debug, Clone, PartialEq)]
pub(super) struct File {
    sha256: String,
    path: String,
    /// `LICENSES/...` or `WHENCE` (the notice is in its entry).
    license: String,
}

#[derive(Debug, Default, PartialEq)]
pub(super) struct Lock {
    tag: String,
    commit: String,
    files: Vec<File>,
    /// `(link, target)`, the target relative to the link's directory.
    links: Vec<(String, String)>,
    /// `(path, why)`: declared by a driver, not shipped.
    skips: Vec<(String, String)>,
    /// `WHENCE` and the license files: `(sha256, path)`.
    meta: Vec<(String, String)>,
}

/// A path inside the firmware tree: relative, no `..`, plain characters.
fn safe_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 255
        && p.bytes().all(|b| b.is_ascii_graphic() && b != b'\\')
        && Path::new(p)
            .components()
            .all(|c| matches!(c, Component::Normal(_)))
}

/// The file a link's target names, from the root of the tree.
fn resolve_link(link: &str, target: &str) -> Option<String> {
    let mut out: Vec<&str> = link.split('/').collect();
    out.pop()?;
    for part in target.split('/') {
        match part {
            "." | "" => {}
            ".." => {
                out.pop()?;
            }
            p => out.push(p),
        }
    }
    Some(out.join("/"))
}

pub(super) fn parse(text: &str) -> Result<Lock, String> {
    let mut l = Lock::default();
    for (i, line) in text.lines().enumerate().take(MAX_LOCK_LINES) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let at = |what: &str| format!("firmware.lock line {}: {what}", i + 1);
        let sha = |s: &str| -> Result<String, String> {
            if super::is_sha256(s) {
                Ok(s.to_owned())
            } else {
                Err(at("not a sha256"))
            }
        };
        let path = |s: &str| -> Result<String, String> {
            if safe_path(s) {
                Ok(s.to_owned())
            } else {
                Err(at("bad path"))
            }
        };
        let w: Vec<&str> = line.split_ascii_whitespace().collect();
        match w.as_slice() {
            ["tag", "=", v] => l.tag = (*v).to_owned(),
            ["commit", "=", v] => l.commit = (*v).to_owned(),
            ["file", s, p, lic] => l.files.push(File {
                sha256: sha(s)?,
                path: path(p)?,
                license: path(lic)?,
            }),
            ["link", p, t] => l.links.push((path(p)?, (*t).to_owned())),
            ["meta", s, p] => l.meta.push((sha(s)?, path(p)?)),
            ["skip", p, why @ ..] if !why.is_empty() => l.skips.push((path(p)?, why.join(" "))),
            _ => return Err(at("unknown line")),
        }
    }
    if l.commit.len() != 40 || !l.commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("firmware.lock: commit = <40 hex digits> is required".into());
    }
    if l.tag.is_empty() {
        return Err("firmware.lock: tag = <linux-firmware tag> is required".into());
    }
    let have: BTreeSet<&str> = l.files.iter().map(|f| f.path.as_str()).collect();
    for (link, target) in &l.links {
        let to = resolve_link(link, target)
            .ok_or_else(|| format!("firmware.lock: link {link} leaves the tree"))?;
        if !have.contains(to.as_str()) {
            return Err(format!("firmware.lock: link {link} → {to}: no such file"));
        }
    }
    let meta: BTreeSet<&str> = l.meta.iter().map(|m| m.1.as_str()).collect();
    if !meta.contains("WHENCE") {
        return Err("firmware.lock: WHENCE must be a meta file (the notices)".into());
    }
    for f in &l.files {
        if !meta.contains(f.license.as_str()) {
            return Err(format!(
                "firmware.lock: {} under {}, which is not a meta file",
                f.path, f.license
            ));
        }
    }
    Ok(l)
}

/// `os check`: the lock parses and has what the image cannot go without.
pub(super) fn check(os: &Path) -> Result<usize, String> {
    let text = std::fs::read_to_string(os.join(LOCK)).map_err(|e| format!("os/{LOCK}: {e}"))?;
    let l = parse(&text)?;
    // Without it the E810 runs in Safe Mode: one queue, no XDP.
    if !l.links.iter().any(|(p, _)| p == "intel/ice/ddp/ice.pkg")
        && !l.files.iter().any(|f| f.path == "intel/ice/ddp/ice.pkg")
    {
        return Err("firmware.lock: intel/ice/ddp/ice.pkg is required".into());
    }
    // G1.6zd: without its GuC a 12th-gen-or-later Intel GPU fails to start
    // ("declaring it wedged") and says so on the console at every boot.
    if !l.files.iter().any(|f| f.path.starts_with("i915/")) {
        return Err("firmware.lock: the i915 firmware (i915/...) is required".into());
    }
    // G1.30: a Wi-Fi card without its firmware never shows its port. One
    // file of each driver family of nics.fragment.
    for (what, dir) in [
        ("iwlwifi", "intel/iwlwifi/"),
        ("mt7921", "mediatek/"),
        ("rtw88", "rtw88/"),
        ("rtw89", "rtw89/"),
    ] {
        if !l.files.iter().any(|f| f.path.starts_with(dir)) {
            return Err(format!(
                "firmware.lock: the {what} firmware ({dir}...) is required"
            ));
        }
    }
    Ok(l.files.len() + l.links.len() + l.meta.len())
}

fn plain_url(commit: &str, path: &str) -> String {
    format!("{REPO}/plain/{path}?id={commit}")
}

/// The files `(sha256, path)` into `cache`, each checked; a wrong one is
/// deleted. A few downloads at a time.
fn fetch_all(lock: &Lock, cache: &Path, want: &[(String, String)]) -> Result<(), String> {
    let missing: Vec<&(String, String)> = want
        .iter()
        .filter(|(sha, p)| sha256_file(&cache.join(p)).ok().as_ref() != Some(sha))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    eprintln!(
        "   linux-firmware {}: downloading {} files",
        lock.tag,
        missing.len()
    );
    let per = missing.len().div_ceil(FETCHERS).max(1);
    std::thread::scope(|s| {
        let workers: Vec<_> = missing
            .chunks(per)
            .map(|chunk| {
                std::thread::Builder::new()
                    .name("firmware-fetch".into())
                    .spawn_scoped(s, move || -> Result<(), String> {
                        for (sha, p) in chunk {
                            let to = cache.join(p);
                            if let Some(dir) = to.parent() {
                                std::fs::create_dir_all(dir)
                                    .map_err(|e| format!("{}: {e}", dir.display()))?;
                            }
                            fetch_one(&plain_url(&lock.commit, p), &to)?;
                            let got = sha256_file(&to)?;
                            if &got != sha {
                                let _ = std::fs::remove_file(&to);
                                return Err(format!("{p}: sha256 {got}, expected {sha} (deleted)"));
                            }
                        }
                        Ok(())
                    })
            })
            .collect();
        let mut result = Ok(());
        for w in workers {
            let r = match w {
                Ok(h) => h.join().unwrap_or_else(|_| Err("fetch thread died".into())),
                Err(e) => Err(format!("fetch thread: {e}")),
            };
            if result.is_ok() {
                result = r;
            }
        }
        result
    })
}

/// One small file, quietly (`download` draws a progress bar per call).
fn fetch_one(url: &str, to: &Path) -> Result<(), String> {
    let st = Command::new("curl")
        .args(["-fsSL", "--retry", "3", "--proto", "=https", "-o"])
        .arg(to)
        .arg(url)
        .status()
        .map_err(|e| format!("curl: {e}"))?;
    if st.success() {
        Ok(())
    } else {
        let _ = std::fs::remove_file(to);
        Err(format!("download of {url} failed: {st}"))
    }
}

/// `WHENCE`'s entries, split at its lines of dashes.
fn whence_sections(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut pos = 0;
    for line in text.split_inclusive('\n') {
        let t = line.trim_end();
        if t.len() >= 20 && t.bytes().all(|b| b == b'-') {
            if let Some(s) = text.get(start..pos) {
                out.push(s);
            }
            start = pos + line.len();
        }
        pos += line.len();
    }
    if let Some(s) = text.get(start..) {
        out.push(s);
    }
    out
}

/// What one `WHENCE` entry says about a file.
#[derive(Debug, Clone, PartialEq)]
struct Whence {
    /// `LICENSES/LICENSE.x`, or `WHENCE` when the notice is in the entry.
    license: String,
    /// The entry states the file may be redistributed.
    redistributable: bool,
}

/// `File:`/`RawFile:` value without its quotes.
fn file_value(line: &str) -> Option<&str> {
    let v = line
        .strip_prefix("File:")
        .or_else(|| line.strip_prefix("RawFile:"))?;
    Some(v.trim().trim_matches('"'))
}

fn is_license_line(line: &str) -> bool {
    let l = line.to_ascii_lowercase();
    l.starts_with("licence:") || l.starts_with("license:")
}

/// Each entry's files give way to the next `Licen[cs]e:` line: an entry can
/// have groups of files under different licenses (`ice`). The text from
/// that line to the next `File:` is what is judged.
fn whence_files(text: &str) -> (BTreeMap<String, Whence>, BTreeMap<String, String>) {
    let mut files = BTreeMap::new();
    let mut links = BTreeMap::new();
    for section in whence_sections(text) {
        let lines: Vec<&str> = section.lines().collect();
        let mut pending: Vec<&str> = Vec::new();
        for (i, line) in lines.iter().enumerate() {
            if let Some(f) = file_value(line) {
                pending.push(f);
            } else if let Some(l) = line.strip_prefix("Link:") {
                if let Some((a, b)) = l.split_once("->") {
                    links.insert(a.trim().to_owned(), b.trim().to_owned());
                }
            } else if is_license_line(line) {
                let rest: Vec<&str> = lines
                    .iter()
                    .skip(i)
                    .take_while(|l| file_value(l).is_none())
                    .copied()
                    .collect();
                let w = judge(&rest.join(" "));
                for f in pending.drain(..) {
                    files.insert(f.to_owned(), w.clone());
                }
            }
        }
        // Files after the entry's last license line: the same license.
        if !pending.is_empty() {
            let w = lines
                .iter()
                .rev()
                .find(|l| is_license_line(l))
                .map(|l| {
                    let i = lines.iter().position(|x| x == l).unwrap_or(0);
                    judge(&lines.get(i..).unwrap_or_default().join(" "))
                })
                .unwrap_or(Whence {
                    license: "WHENCE".into(),
                    redistributable: false,
                });
            for f in pending {
                files.insert(f.to_owned(), w.clone());
            }
        }
    }
    (files, links)
}

/// The license an entry's text names and whether it allows redistribution.
fn judge(text: &str) -> Whence {
    let license = text
        .split(|c: char| c.is_whitespace() || c == ',' || c == '(' || c == ')')
        .map(|w| w.trim_end_matches('.'))
        .find(|w| {
            (w.starts_with("LICENSE") || w.starts_with("LICENCE") || w.starts_with("GPL-"))
                && w.len() > 7
        })
        .map_or_else(
            || "WHENCE".to_owned(),
            // An SPDX id names the license, not a file: the tree has `GPL-2.0`
            // for every GPL-2.0-only and GPL-2.0-or-later.
            |w| match w {
                _ if w.starts_with("GPL-2") => "LICENSES/GPL-2.0".to_owned(),
                _ if w.starts_with("GPL-3") => "LICENSES/GPL-3.0-only".to_owned(),
                _ => format!("LICENSES/{w}"),
            },
        );
    let flat = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase();
    let redistributable = [
        "redistributable",
        "permission is hereby granted for the distribution",
        "redistribution and use",
        "gplv2",
        "gpl-2",
        "gpl version 2",
        "dual gpl",
    ]
    .iter()
    .any(|w| flat.contains(w));
    // "Allegedly GPLv2, but no source visible": the GPL asks for the source
    // and nobody has it, so that claim does not let us ship the binary. A BSD
    // alternative in the same line does.
    let gpl_without_source = (flat.contains("no source visible") || flat.contains("allegedly gpl"))
        && !flat.contains("bsd");
    Whence {
        license,
        redistributable: redistributable && !gpl_without_source,
    }
}

/// The entries of `WHENCE` that name a shipped file: the notices that go
/// with the firmware, without the hundreds of other drivers'.
fn selected_whence(whence: &str, lock: &Lock) -> String {
    let shipped: BTreeSet<&str> = lock.files.iter().map(|f| f.path.as_str()).collect();
    whence_sections(whence)
        .into_iter()
        .filter(|s| {
            s.lines()
                .filter_map(file_value)
                .any(|f| shipped.contains(f))
        })
        .map(str::trim)
        .collect::<Vec<_>>()
        .join("\n\n--------------------------------------------------------------------------\n\n")
}

/// Downloads what the lock pins and lays it out as the image will have it:
/// `lib/firmware/...` and the licenses. The directory `corerouter-firmware`
/// installs. The same lock gives the same tree, whatever was there before.
pub(super) fn stage(os: &Path, top: &Path) -> Result<PathBuf, String> {
    let text = std::fs::read_to_string(os.join(LOCK)).map_err(|e| format!("os/{LOCK}: {e}"))?;
    let lock = parse(&text)?;
    let cache = os.join("dl").join(format!("linux-firmware-{}", lock.tag));
    let mut all: Vec<(String, String)> = lock.meta.clone();
    all.extend(
        lock.files
            .iter()
            .map(|f| (f.sha256.clone(), f.path.clone())),
    );
    fetch_all(&lock, &cache, &all)?;
    let root = top.join("firmware-stage");
    if root.exists() {
        std::fs::remove_dir_all(&root).map_err(|e| format!("{}: {e}", root.display()))?;
    }
    let fw = root.join("lib/firmware");
    let copy = |from: &Path, to: &Path| -> Result<(), String> {
        if let Some(d) = to.parent() {
            std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        std::fs::copy(from, to).map_err(|e| format!("{}: {e}", to.display()))?;
        Ok(())
    };
    for f in &lock.files {
        copy(&cache.join(&f.path), &fw.join(&f.path))?;
    }
    for (link, target) in &lock.links {
        let at = fw.join(link);
        if let Some(d) = at.parent() {
            std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        std::os::unix::fs::symlink(target, &at).map_err(|e| format!("{}: {e}", at.display()))?;
    }
    let licenses = root.join(LICENSE_DIR);
    for (_, p) in &lock.meta {
        if p != "WHENCE" {
            let name = p.rsplit('/').next().unwrap_or(p);
            copy(&cache.join(p), &licenses.join(name))?;
        }
    }
    let whence =
        std::fs::read_to_string(cache.join("WHENCE")).map_err(|e| format!("WHENCE: {e}"))?;
    std::fs::write(licenses.join("WHENCE"), selected_whence(&whence, &lock))
        .map_err(|e| format!("WHENCE: {e}"))?;
    Ok(root)
}

/// The `firmware=` values of a module's bytes (its `.modinfo` section is a
/// list of `key=value\0`).
fn declared_in_ko(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|&b| b == 0)
        .filter_map(|s| s.strip_prefix(b"firmware="))
        .filter_map(|v| std::str::from_utf8(v).ok())
        .filter(|v| safe_path(v))
        .map(str::to_owned)
        .collect()
}

/// `<module>.firmware=<file>` lines of `modules.builtin.modinfo`, only for
/// the modules `modules.builtin` lists under [`DRIVERS`].
fn declared_builtin(builtin: &str, modinfo: &[u8]) -> Vec<String> {
    let ours: BTreeSet<String> = builtin
        .lines()
        .filter(|l| DRIVERS.iter().any(|d| l.starts_with(d)))
        .filter_map(|l| l.rsplit('/').next())
        .filter_map(|f| f.split(".ko").next())
        .map(|n| n.replace('-', "_"))
        .collect();
    let mut out = Vec::new();
    for rec in modinfo.split(|&b| b == 0) {
        let Ok(rec) = std::str::from_utf8(rec) else {
            continue;
        };
        if let Some((module, file)) = rec.split_once(".firmware=")
            && ours.contains(module)
            && safe_path(file)
        {
            out.push(file.to_owned());
        }
    }
    out
}

pub(super) fn ko_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            ko_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "ko") {
            out.push(p);
        }
    }
}

/// What the kernel's drivers of [`DRIVERS`] declare: built in, and the
/// modules in those directories.
fn declared(modules: &Path) -> Result<BTreeSet<String>, String> {
    let builtin = std::fs::read_to_string(modules.join("modules.builtin"))
        .map_err(|e| format!("{}: {e}", modules.display()))?;
    let info = std::fs::read(modules.join("modules.builtin.modinfo"))
        .map_err(|e| format!("{}: {e}", modules.display()))?;
    let mut out: BTreeSet<String> = declared_builtin(&builtin, &info).into_iter().collect();
    let mut kos = Vec::new();
    for d in DRIVERS {
        ko_files(&modules.join(d), &mut kos);
    }
    for ko in kos {
        let b = std::fs::read(&ko).map_err(|e| format!("{}: {e}", ko.display()))?;
        out.extend(declared_in_ko(&b));
    }
    Ok(out)
}

/// The `lib/modules/<version>` of a target tree.
fn modules_dir(target: &Path) -> Result<PathBuf, String> {
    std::fs::read_dir(target.join("lib/modules"))
        .map_err(|e| format!("{}: {e}", target.display()))?
        .flatten()
        .map(|e| e.path())
        .find(|p| p.is_dir())
        .ok_or_else(|| "the image has no lib/modules".to_owned())
}

/// After the build: the image has every locked file with its hash, the
/// links resolve, each license is there, and every file the drivers declare
/// is in the image or in a `skip` line. Returns the files checked.
pub(super) fn verify(os: &Path, target: &Path) -> Result<usize, String> {
    let text = std::fs::read_to_string(os.join(LOCK)).map_err(|e| format!("os/{LOCK}: {e}"))?;
    let lock = parse(&text)?;
    let fw = target.join("lib/firmware");
    for f in &lock.files {
        let got = sha256_file(&fw.join(&f.path))?;
        if got != f.sha256 {
            return Err(format!(
                "image: lib/firmware/{}: sha256 {got}, locked {}",
                f.path, f.sha256
            ));
        }
    }
    for (link, _) in &lock.links {
        if !fw.join(link).is_file() {
            return Err(format!("image: lib/firmware/{link} does not resolve"));
        }
    }
    let licenses = target.join(LICENSE_DIR);
    for (_, p) in &lock.meta {
        let name = p.rsplit('/').next().unwrap_or(p);
        if !licenses.join(name).is_file() {
            return Err(format!("image: {LICENSE_DIR}/{name} is missing"));
        }
    }
    let modules = modules_dir(target)?;
    // G1.30: with the Wi-Fi stack in the image, cfg80211 needs its signed
    // regulatory database (it is not linux-firmware's, so not in the lock):
    // without it no country can be set and 5 GHz is listen-only. A second
    // build of the same tree once lost it.
    if modules.join("kernel/net/wireless/cfg80211.ko").is_file() {
        for f in ["regulatory.db", "regulatory.db.p7s"] {
            if !fw.join(f).is_file() {
                return Err(format!(
                    "image: lib/firmware/{f} is missing (cfg80211 is in the image; package wireless-regdb)"
                ));
            }
        }
    }
    let wanted = declared(&modules)?;
    let missing = undeclared(&wanted, &lock);
    if !missing.is_empty() {
        return Err(format!(
            "drivers declare firmware that is not in the image nor in a skip line: {} \
             (cargo xtask os firmware-lock --tag {})",
            missing.join(" "),
            lock.tag
        ));
    }
    Ok(lock.files.len())
}

fn undeclared(wanted: &BTreeSet<String>, lock: &Lock) -> Vec<String> {
    let mut known: BTreeSet<&str> = lock.files.iter().map(|f| f.path.as_str()).collect();
    known.extend(lock.links.iter().map(|(p, _)| p.as_str()));
    known.extend(lock.skips.iter().map(|(p, _)| p.as_str()));
    wanted
        .iter()
        .filter(|w| !known.contains(w.as_str()))
        .cloned()
        .collect()
}

/// A version in an `iwlwifi` firmware's name: `-89.ucode` (the API scheme)
/// or `-c101.ucode` (the core scheme, newer: it sorts after every API).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct IwlVersion {
    core: bool,
    n: u32,
}

/// The first core version, and the API version the driver goes to below it
/// (`iwl-drv.c`, `iwl_request_firmware`: from `ENCODE_CORE_AS_API(99)` it
/// goes to 101, "last API-scheme number below core 99").
const IWL_FIRST_CORE: u32 = 99;
const IWL_LAST_API: u32 = 101;

/// `iwlwifi-so-a0-gf-a0-89.ucode` → (`so-a0-gf-a0`, API 89).
fn iwl_name(name: &str) -> Option<(&str, IwlVersion)> {
    let rest = name.strip_prefix("iwlwifi-")?.strip_suffix(".ucode")?;
    let (prefix, v) = rest.rsplit_once('-')?;
    let (core, digits) = match v.strip_prefix('c') {
        Some(d) => (true, d),
        None => (false, v),
    };
    if prefix.is_empty() || digits.is_empty() || digits.len() > 4 {
        return None;
    }
    let n = digits.parse().ok()?;
    Some((prefix, IwlVersion { core, n }))
}

/// G1.30: what `iwlwifi` asks for is not what it declares. `MODULE_FIRMWARE`
/// names the newest version the driver knows (`-100.ucode`, `-c99.ucode`),
/// for the chip steppings it lists; at run time the driver makes the name
/// from the stepping the card has and tries from the newest version down to
/// the oldest it accepts (`iwl-drv.c`, `iwl_request_firmware`), and then asks
/// for `<prefix>.pnvm`, which it declares nowhere (`fw/pnvm.c`).
/// linux-firmware has, per prefix, the versions that were published: of the
/// names declared for Linux 6.18, 26 are not there.
///
/// So, for every prefix of the tree (the root links of `WHENCE`) that the
/// built driver knows (it declares that prefix, or another stepping of the
/// same chip: the name's first part), this gives the newest version the
/// driver tries (not newer than what it declares) and the prefix's `.pnvm`.
/// A card of a family that was not built (`iwldvm`) declares nothing and
/// gets nothing.
fn iwlwifi_requests(
    declared: &BTreeSet<String>,
    links: &BTreeMap<String, String>,
) -> BTreeSet<String> {
    let mut by_prefix: BTreeMap<&str, IwlVersion> = BTreeMap::new();
    let mut by_chip: BTreeMap<&str, IwlVersion> = BTreeMap::new();
    for (prefix, v) in declared.iter().filter_map(|d| iwl_name(d)) {
        let chip = prefix.split('-').next().unwrap_or(prefix);
        for (map, key) in [(&mut by_prefix, prefix), (&mut by_chip, chip)] {
            let e = map.entry(key).or_insert(v);
            *e = (*e).max(v);
        }
    }
    let mut newest: BTreeMap<&str, IwlVersion> = BTreeMap::new();
    for (prefix, v) in links.keys().filter_map(|l| iwl_name(l)) {
        let chip = prefix.split('-').next().unwrap_or(prefix);
        let Some(bound) = by_prefix.get(prefix).or_else(|| by_chip.get(chip)) else {
            continue;
        };
        let tried = match (v.core, bound.core) {
            (true, true) => (IWL_FIRST_CORE..=bound.n).contains(&v.n),
            (true, false) => false,
            (false, true) => v.n <= IWL_LAST_API,
            (false, false) => v.n <= bound.n,
        };
        if tried {
            let e = newest.entry(prefix).or_insert(v);
            *e = (*e).max(v);
        }
    }
    let mut out = BTreeSet::new();
    for (prefix, v) in newest {
        let c = if v.core { "c" } else { "" };
        out.insert(format!("iwlwifi-{prefix}-{c}{}.ucode", v.n));
        let pnvm = format!("iwlwifi-{prefix}.pnvm");
        if links.contains_key(&pnvm) {
            out.insert(pnvm);
        }
    }
    out
}

/// Builds the lock from what the drivers declare and what `WHENCE` says.
/// `hash` gives a file's sha256 (a download, in real use).
fn build_lock(
    tag: &str,
    commit: &str,
    wanted: &BTreeSet<String>,
    whence: &str,
    mut hash: impl FnMut(&str) -> Result<Option<String>, String>,
) -> Result<Lock, String> {
    let (files, links) = whence_files(whence);
    let mut l = Lock {
        tag: tag.into(),
        commit: commit.into(),
        ..Lock::default()
    };
    let mut licenses = BTreeSet::new();
    let mut to_ship = BTreeMap::new();
    let requested = iwlwifi_requests(wanted, &links);
    for name in wanted.iter().chain(requested.difference(wanted)) {
        let real = match links.get(name) {
            Some(target) => match resolve_link(name, target) {
                Some(real) => real,
                None => {
                    l.skips.push((name.clone(), "link leaves the tree".into()));
                    continue;
                }
            },
            None => name.clone(),
        };
        let Some(w) = files.get(&real) else {
            let why = if iwl_name(name).is_some() {
                // `iwlwifi_requests` shipped the one the driver ends up with.
                format!("not in linux-firmware {tag}: iwlwifi declares the newest version it knows")
            } else {
                format!("not in linux-firmware {tag}")
            };
            l.skips.push((name.clone(), why));
            continue;
        };
        if !w.redistributable {
            l.skips.push((
                name.clone(),
                "WHENCE states no permission to redistribute".into(),
            ));
            continue;
        }
        if links.contains_key(name) {
            l.links
                .push((name.clone(), links.get(name).cloned().unwrap_or_default()));
        }
        to_ship.insert(real, w.clone());
    }
    for (path, w) in to_ship {
        let Some(sha256) = hash(&path)? else {
            return Err(format!(
                "{path}: WHENCE lists it, but it is not in the tree"
            ));
        };
        if w.license != "WHENCE" {
            licenses.insert(w.license.clone());
        }
        l.files.push(File {
            sha256,
            path,
            license: w.license,
        });
    }
    for p in std::iter::once("WHENCE".to_owned()).chain(licenses) {
        let Some(sha) = hash(&p)? else {
            return Err(format!("{p}: not in the tree"));
        };
        l.meta.push((sha, p));
    }
    Ok(l)
}

fn render(l: &Lock) -> String {
    let mut s = String::from(
        "# Generated by `cargo xtask os firmware-lock` (G1.6j, docs/os-image.md).\n\
         # What the kernel's network and screen drivers declare, from linux-firmware, with the\n\
         # license each file's WHENCE entry names. `skip`: declared, not shipped.\n\
         # iwlwifi: per chip, the newest version the driver tries, and its .pnvm (G1.30).\n",
    );
    s.push_str(&format!("tag = {}\ncommit = {}\n\n", l.tag, l.commit));
    for (sha, p) in &l.meta {
        s.push_str(&format!("meta {sha} {p}\n"));
    }
    s.push('\n');
    for f in &l.files {
        s.push_str(&format!("file {} {} {}\n", f.sha256, f.path, f.license));
    }
    if !l.links.is_empty() {
        s.push('\n');
    }
    for (p, t) in &l.links {
        s.push_str(&format!("link {p} {t}\n"));
    }
    if !l.skips.is_empty() {
        s.push('\n');
    }
    for (p, why) in &l.skips {
        s.push_str(&format!("skip {p} {why}\n"));
    }
    s
}

/// `cargo xtask os firmware-lock --tag T`: needs a built image (its target
/// tree says what the drivers declare).
pub(super) fn lock_cmd(root: &Path, target: &Path, args: &[String]) -> Result<(), String> {
    let [flag, tag] = args else {
        return Err("usage: cargo xtask os firmware-lock --tag <linux-firmware tag>".into());
    };
    if flag != "--tag" {
        return Err(format!("unknown argument '{flag}'"));
    }
    let refs = Command::new("git")
        .args(["ls-remote", "--tags", REPO])
        .arg(format!("refs/tags/{tag}^{{}}"))
        .arg(format!("refs/tags/{tag}"))
        .output()
        .map_err(|e| format!("git ls-remote: {e}"))?;
    let refs = String::from_utf8_lossy(&refs.stdout).into_owned();
    // An annotated tag's `^{}` (the commit) wins over the tag object.
    let commit = refs
        .lines()
        .find(|l| l.ends_with("^{}"))
        .or_else(|| refs.lines().next())
        .and_then(|l| l.split_whitespace().next())
        .ok_or_else(|| format!("linux-firmware has no tag {tag}"))?
        .to_owned();
    let os = root.join("os");
    let cache = os.join("dl").join(format!("linux-firmware-{tag}"));
    std::fs::create_dir_all(&cache).map_err(|e| e.to_string())?;
    let whence_path = cache.join("WHENCE");
    download(&plain_url(&commit, "WHENCE"), &whence_path)?;
    let whence = std::fs::read_to_string(&whence_path).map_err(|e| format!("WHENCE: {e}"))?;
    let wanted = declared(&modules_dir(target)?)?;
    let lock = build_lock(tag, &commit, &wanted, &whence, |p| {
        let to = cache.join(p);
        if let Some(d) = to.parent() {
            std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        if !to.exists() && fetch_one(&plain_url(&commit, p), &to).is_err() {
            return Ok(None);
        }
        sha256_file(&to).map(Some)
    })?;
    let out = os.join(LOCK);
    std::fs::write(&out, render(&lock)).map_err(|e| format!("{}: {e}", out.display()))?;
    let bytes: u64 = lock
        .files
        .iter()
        .filter_map(|f| std::fs::metadata(cache.join(&f.path)).ok())
        .map(|m| m.len())
        .sum();
    eprintln!(
        "{}: {} files ({bytes} bytes), {} links, {} licenses, {} skipped, of {} declared",
        out.display(),
        lock.files.len(),
        lock.links.len(),
        lock.meta.len().saturating_sub(1),
        lock.skips.len(),
        wanted.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "2f51946732a6e93a224fec4ab49b93ebd106aef6c52b1ebfa490795a19fac21f";

    const WHENCE: &str = "\
Intro text.

--------------------------------------------------------------------------

Driver: ice - Intel

File: intel/ice/ddp/ice-1.3.43.0.pkg
Link: intel/ice/ddp/ice.pkg -> ice-1.3.43.0.pkg

License: Redistributable. See LICENSE.ice for details

File: intel/ice/ddp-comms/ice_comms-1.3.55.0.pkg

License: Redistributable. See LICENSE.ice_enhanced for details

--------------------------------------------------------------------------

Driver: tg3 -- Broadcom

File: tigon/tg3.bin

Licence:
 * Firmware is:
 *\tPermission is hereby granted for the distribution of this firmware
 *\tdata in hexadecimal or equivalent format.

--------------------------------------------------------------------------

Driver: foo - no terms

File: \"foo/quoted.bin\"

Licence: Allegedly GPLv2+, but no source visible.
Unknown terms for bar.

--------------------------------------------------------------------------

Driver: secret

File: secret/blob.bin

Licence: Proprietary. All rights reserved.
";

    fn lock_text() -> String {
        format!(
            "tag = 20261019\ncommit = {}\n\
             meta {SHA} WHENCE\nmeta {SHA} LICENSES/LICENSE.ice\n\
             file {SHA} intel/ice/ddp/ice-1.3.43.0.pkg LICENSES/LICENSE.ice\n\
             file {SHA} tigon/tg3.bin WHENCE\n\
             link intel/ice/ddp/ice.pkg ice-1.3.43.0.pkg\n\
             skip nfp/x.bin not in linux-firmware\n",
            "a".repeat(40)
        )
    }

    #[test]
    fn a_good_lock_parses_and_renders_back() {
        let l = parse(&lock_text()).unwrap();
        assert_eq!(l.files.len(), 2);
        assert_eq!(
            l.links,
            [("intel/ice/ddp/ice.pkg".into(), "ice-1.3.43.0.pkg".into())]
        );
        assert_eq!(l.skips[0].1, "not in linux-firmware");
        assert_eq!(parse(&render(&l)).unwrap(), l);
    }

    #[test]
    fn bad_locks_are_refused() {
        let t = lock_text();
        for (from, to, why) in [
            ("commit = aaaa", "commit = zz", "commit"),
            ("tag = 20261019\n", "", "tag"),
            ("tigon/tg3.bin WHENCE", "../../etc/passwd WHENCE", "path"),
            ("tigon/tg3.bin WHENCE", "/etc/passwd WHENCE", "path"),
            (
                "link intel/ice/ddp/ice.pkg ice-1.3.43.0.pkg",
                "link a/b ../../../x",
                "leaves",
            ),
            (
                "link intel/ice/ddp/ice.pkg ice-1.3.43.0.pkg",
                "link a/b nope",
                "no such",
            ),
            (
                "meta 2f51946732a6e93a224fec4ab49b93ebd106aef6c52b1ebfa490795a19fac21f WHENCE",
                "",
                "WHENCE",
            ),
            (
                "meta 2f51946732a6e93a224fec4ab49b93ebd106aef6c52b1ebfa490795a19fac21f LICENSES/LICENSE.ice\n",
                "",
                "meta",
            ),
            (
                "skip nfp/x.bin not in linux-firmware",
                "skip nfp/x.bin",
                "unknown",
            ),
            ("file 2f5", "file xxx", "sha"),
        ] {
            let bad = t.replacen(from, to, 1);
            assert_ne!(bad, t, "{from}");
            assert!(parse(&bad).is_err(), "{from} → {to} ({why})");
        }
    }

    #[test]
    fn garbage_does_not_panic() {
        for g in [
            "",
            "\0",
            "file",
            "tag =",
            "= = =",
            "link a",
            "\u{fffd}\n\n",
            "commit = x",
        ] {
            assert!(parse(g).is_err(), "{g:?}");
        }
    }

    #[test]
    fn iwlwifi_gets_the_newest_version_the_driver_tries() {
        // What Linux 6.18 declares (the newest it knows, the steppings it
        // lists) and what linux-firmware 20261019 has.
        let declared: BTreeSet<String> = [
            "iwlwifi-so-a0-gf-a0-100.ucode",
            "iwlwifi-so-a0-gf-a0.pnvm",
            "iwlwifi-Qu-b0-hr-b0-100.ucode",
            "iwlwifi-cc-a0-77.ucode",
            "iwlwifi-7265D-29.ucode",
            "iwlwifi-bz-a0-fm-c0-c99.ucode",
            "iwlwifi-sc-a0-fm-c0-c99.ucode",
            "tigon/tg3.bin",
        ]
        .map(str::to_owned)
        .into();
        let links: BTreeMap<String, String> = [
            "iwlwifi-so-a0-gf-a0-86.ucode",
            "iwlwifi-so-a0-gf-a0-89.ucode",
            "iwlwifi-so-a0-gf-a0.pnvm",
            "iwlwifi-so-a0-hr-b0-89.ucode",
            "iwlwifi-Qu-b0-hr-b0-74.ucode",
            "iwlwifi-Qu-b0-hr-b0-77.ucode",
            "iwlwifi-cc-a0-77.ucode",
            "iwlwifi-7265D-22.ucode",
            "iwlwifi-7265D-29.ucode",
            // The card's real stepping, which the driver does not declare;
            // c101 and later are for a newer kernel.
            "iwlwifi-bz-b0-fm-c0-100.ucode",
            "iwlwifi-bz-b0-fm-c0-101.ucode",
            "iwlwifi-bz-b0-fm-c0-c101.ucode",
            "iwlwifi-bz-b0-fm-c0.pnvm",
            // Nothing this kernel can load.
            "iwlwifi-sc-a0-fm-c0-c101.ucode",
            // iwldvm is not built: not declared, not shipped.
            "iwlwifi-6000g2a-6.ucode",
            "iwlwifi-1000-5.ucode",
            "intel/ice/ddp/ice.pkg",
        ]
        .into_iter()
        .map(|l| (l.to_owned(), format!("intel/iwlwifi/{l}")))
        .collect();
        let got: Vec<String> = iwlwifi_requests(&declared, &links).into_iter().collect();
        assert_eq!(
            got,
            [
                "iwlwifi-7265D-29.ucode",
                "iwlwifi-Qu-b0-hr-b0-77.ucode",
                "iwlwifi-bz-b0-fm-c0-101.ucode",
                "iwlwifi-bz-b0-fm-c0.pnvm",
                "iwlwifi-cc-a0-77.ucode",
                "iwlwifi-so-a0-gf-a0-89.ucode",
                "iwlwifi-so-a0-gf-a0.pnvm",
                "iwlwifi-so-a0-hr-b0-89.ucode",
            ]
        );
        // A newer kernel that declares core 103 takes the core files.
        let newer: BTreeSet<String> = ["iwlwifi-bz-b0-fm-c0-c103.ucode".to_owned()].into();
        assert_eq!(
            iwlwifi_requests(&newer, &links).into_iter().next().unwrap(),
            "iwlwifi-bz-b0-fm-c0-c101.ucode"
        );
        for bad in [
            "iwlwifi-.ucode",
            "iwlwifi-x-.ucode",
            "iwlwifi-x-c.ucode",
            "iwlwifi-x-99999.ucode",
            "x-1.ucode",
            "iwlwifi-so-a0.pnvm",
        ] {
            assert_eq!(iwl_name(bad), None, "{bad}");
        }
    }

    #[test]
    fn the_lock_follows_iwlwifi_to_the_file_it_loads() {
        let whence = "\
Driver: iwlwifi - Intel Wireless Wifi

File: intel/iwlwifi/iwlwifi-so-a0-gf-a0-89.ucode
Link: iwlwifi-so-a0-gf-a0-89.ucode -> intel/iwlwifi/iwlwifi-so-a0-gf-a0-89.ucode
File: intel/iwlwifi/iwlwifi-so-a0-gf-a0.pnvm
Link: iwlwifi-so-a0-gf-a0.pnvm -> intel/iwlwifi/iwlwifi-so-a0-gf-a0.pnvm

Licence: Redistributable. See LICENCE.iwlwifi_firmware for details
";
        let wanted: BTreeSet<String> = ["iwlwifi-so-a0-gf-a0-100.ucode".to_owned()].into();
        let l = build_lock("20261019", &"a".repeat(40), &wanted, whence, |_| {
            Ok(Some(SHA.to_owned()))
        })
        .unwrap();
        let files: Vec<&str> = l.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            files,
            [
                "intel/iwlwifi/iwlwifi-so-a0-gf-a0-89.ucode",
                "intel/iwlwifi/iwlwifi-so-a0-gf-a0.pnvm"
            ]
        );
        assert_eq!(l.links.len(), 2);
        assert_eq!(l.skips.len(), 1);
        assert!(
            l.skips[0].1.contains("newest version it knows"),
            "{:?}",
            l.skips
        );
        // What the build checks afterwards: the declared name is accounted for.
        assert!(undeclared(&wanted, &l).is_empty());
        parse(&render(&l)).unwrap();
    }

    #[test]
    fn whence_says_who_may_ship_what() {
        let (files, links) = whence_files(WHENCE);
        let ice = files.get("intel/ice/ddp/ice-1.3.43.0.pkg").unwrap();
        assert_eq!(ice.license, "LICENSES/LICENSE.ice");
        assert!(ice.redistributable);
        // Two groups of files under two licenses in one entry.
        let comms = files
            .get("intel/ice/ddp-comms/ice_comms-1.3.55.0.pkg")
            .unwrap();
        assert_eq!(comms.license, "LICENSES/LICENSE.ice_enhanced");
        let tg3 = files.get("tigon/tg3.bin").unwrap();
        assert_eq!(tg3.license, "WHENCE");
        assert!(tg3.redistributable);
        assert!(!files.get("secret/blob.bin").unwrap().redistributable);
        assert!(files.contains_key("foo/quoted.bin"));
        assert_eq!(
            links.get("intel/ice/ddp/ice.pkg").unwrap(),
            "ice-1.3.43.0.pkg"
        );
    }

    #[test]
    fn the_lock_ships_only_what_may_be_shipped() {
        let wanted: BTreeSet<String> = [
            "intel/ice/ddp/ice.pkg",
            "tigon/tg3.bin",
            "secret/blob.bin",
            "nowhere/x.bin",
        ]
        .map(str::to_owned)
        .into();
        let l = build_lock("T", &"a".repeat(40), &wanted, WHENCE, |_| {
            Ok(Some(SHA.to_owned()))
        })
        .unwrap();
        let paths: Vec<&str> = l.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(paths, ["intel/ice/ddp/ice-1.3.43.0.pkg", "tigon/tg3.bin"]);
        assert_eq!(
            l.links,
            [("intel/ice/ddp/ice.pkg".into(), "ice-1.3.43.0.pkg".into())]
        );
        let skipped: Vec<&str> = l.skips.iter().map(|s| s.0.as_str()).collect();
        assert_eq!(skipped, ["nowhere/x.bin", "secret/blob.bin"]);
        let meta: Vec<&str> = l.meta.iter().map(|m| m.1.as_str()).collect();
        assert_eq!(meta, ["WHENCE", "LICENSES/LICENSE.ice"]);
        // What it generates is a valid lock.
        assert_eq!(parse(&render(&l)).unwrap(), l);
        assert!(undeclared(&wanted, &l).is_empty());
        let more: BTreeSet<String> = ["new/fw.bin".to_owned()].into();
        assert_eq!(undeclared(&more, &l), ["new/fw.bin"]);
    }

    #[test]
    fn a_listed_file_absent_from_the_tree_stops_the_lock() {
        let wanted: BTreeSet<String> = ["tigon/tg3.bin".to_owned()].into();
        let r = build_lock("T", &"a".repeat(40), &wanted, WHENCE, |_| Ok(None));
        assert!(r.unwrap_err().contains("not in the tree"));
    }

    #[test]
    fn only_the_shipped_notices_go_in_the_image() {
        let l = parse(&lock_text()).unwrap();
        let s = selected_whence(WHENCE, &l);
        assert!(s.contains("Driver: ice"));
        assert!(s.contains("Permission is hereby granted"));
        assert!(!s.contains("Driver: secret"));
        assert!(!s.contains("Intro text"));
    }

    #[test]
    fn links_resolve_inside_the_tree() {
        assert_eq!(resolve_link("a/b/c", "d").as_deref(), Some("a/b/d"));
        assert_eq!(resolve_link("a/b/c", "../d").as_deref(), Some("a/d"));
        assert_eq!(resolve_link("c", "d").as_deref(), Some("d"));
        assert_eq!(resolve_link("c", "../d"), None);
    }

    #[test]
    fn modinfo_of_modules_and_of_the_kernel() {
        let ko =
            b"\x7fELF\0license=GPL\0firmware=intel/ice/ddp/ice.pkg\0firmware=../evil\0vermagic=6\0";
        assert_eq!(declared_in_ko(ko), ["intel/ice/ddp/ice.pkg"]);
        let builtin = "kernel/drivers/net/ethernet/broadcom/tg3.ko\nkernel/drivers/gpu/drm/i915/i915.ko\nkernel/sound/snd.ko\nkernel/drivers/net/usb/r-8152.ko\n";
        let info = b"tg3.license=GPL\0tg3.firmware=tigon/tg3.bin\0i915.firmware=i915/a.bin\0snd.firmware=snd/a.bin\0r_8152.firmware=rtl_nic/a.fw\0";
        assert_eq!(
            declared_builtin(builtin, info),
            ["tigon/tg3.bin", "i915/a.bin", "rtl_nic/a.fw"]
        );
    }

    /// The lock in the tree: the check of `os check`, run with the tests.
    #[test]
    fn the_tree_lock_is_valid() {
        let os = Path::new(env!("CARGO_MANIFEST_DIR")).join("../os");
        assert!(check(&os).unwrap() > 0);
    }

    #[test]
    fn gpl_with_no_source_is_not_redistributable() {
        let cases = [
            ("Licence: Allegedly GPLv2, but no source visible.", false),
            (
                "Licence: Allegedly GPLv2+, but no source visible. Marked:",
                false,
            ),
            (
                "Licence: GPLv2 or OpenIB.org BSD license, no source visible",
                true,
            ),
            ("Licence: GPLv2 or later. See GPL-2.0 for details.", true),
            (
                "Licence: Redistributable. See LICENSE.r8169 for details.",
                true,
            ),
            ("Licence: Unknown", false),
        ];
        for (text, want) in cases {
            assert_eq!(judge(text).redistributable, want, "{text}");
        }
        let spdx = "Licence: x. SPDX-License-Identifier: GPL-2.0-only";
        assert_eq!(judge(spdx).license, "LICENSES/GPL-2.0");
        let named = "Licence: GPLv2. See GPL-2.0-only for details.";
        assert_eq!(judge(named).license, "LICENSES/GPL-2.0");
    }
}

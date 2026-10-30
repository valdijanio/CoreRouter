//! processo (release da imagem): the release key and the local publication
//! of a version's router image (docs/release.md).
//!
//! - `os release-key init [--dir D]`: a new release key pair, encrypted
//!   with a passphrase, in a directory outside the repository and the build
//!   disk (default `~/.config/corerouter/release-key`, 0700). Its public key
//!   goes into `os/keys/release/` by a PR: development images then trust it
//!   too, release images trust only it.
//! - `os release-key check [--dir D]`: the passphrase opens the key (the
//!   backup check), and whether its public key is in `os/keys/release/`.
//! - `os release --tag vX.Y.Z`: checks that the checkout is exactly that
//!   tag, builds the image apart from the development build, signs it with
//!   the release key (decrypted into `$XDG_RUNTIME_DIR` for the build and
//!   wiped after), checks the result, writes the SHA-256 sums and uploads
//!   them to the **draft** GitHub Release of the tag. It never creates a
//!   tag, never creates or publishes a Release; the key never leaves the
//!   machine.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;
use sha2::{Digest, Sha256};

use super::{ReleaseBuild, ab, out};
use crate::vm_lab::sha256_file;

/// The release public keys, in the repository (one `<id>.pub` each).
pub const RELEASE_KEYS: &str = "os/keys/release";
/// The file `corerouter-image release-key` writes.
const KEY_FILE: &str = "release-image-key.enc";
const BUILD_DISK: &str = "/srv/build";
const USAGE_KEY: &str = "usage: cargo xtask os release-key <init|check> [--dir DIR]";
const USAGE: &str = "usage: cargo xtask os release --tag vX.Y.Z [--key-dir DIR] [--dry-run] [--no-build] [--repo OWNER/NAME] [--jobs N] [--top-jobs N]";

/// `~/.config/corerouter/release-key` (`$XDG_CONFIG_HOME` first).
fn default_key_dir() -> Result<PathBuf, String> {
    let config = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        Some(c) => PathBuf::from(c),
        None => PathBuf::from(std::env::var_os("HOME").ok_or("$HOME not set")?).join(".config"),
    };
    Ok(config.join("corerouter/release-key"))
}

/// The path with its existing part resolved (symlinks), the rest appended.
fn resolve_partial(p: &Path) -> PathBuf {
    let abs = if p.is_absolute() {
        p.to_owned()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    let mut rest = Vec::new();
    let mut cur = abs.as_path();
    loop {
        if let Ok(c) = std::fs::canonicalize(cur) {
            let mut out = c;
            for r in rest.iter().rev() {
                out.push(r);
            }
            return out;
        }
        match (cur.parent(), cur.file_name()) {
            (Some(parent), Some(name)) => {
                rest.push(name.to_owned());
                cur = parent;
            }
            _ => return abs,
        }
    }
}

/// Where a release key may not live: inside the repository (it would be
/// one `git add` away from a public repo) or on the build disk (shared by
/// every build and session of the machine).
fn key_dir_refusal(dir: &Path, root: &Path) -> Option<String> {
    let dir = resolve_partial(dir);
    let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_owned());
    if dir.starts_with(&root) {
        return Some(format!(
            "{} is inside the repository ({}): the release key lives outside it",
            dir.display(),
            root.display()
        ));
    }
    let disk = resolve_partial(Path::new(BUILD_DISK));
    if dir.starts_with(&disk) {
        return Some(format!(
            "{} is on the build disk ({BUILD_DISK}), shared by every build: the release key lives outside it",
            dir.display()
        ));
    }
    None
}

pub fn release_key(root: &Path, args: &[String]) -> Result<(), String> {
    let (Some(sub @ ("init" | "check")), rest) = (
        args.first().map(String::as_str),
        args.get(1..).unwrap_or(&[]),
    ) else {
        return Err(USAGE_KEY.into());
    };
    let mut dir = None;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--dir" => dir = Some(PathBuf::from(it.next().ok_or("--dir needs a directory")?)),
            other => return Err(format!("unknown argument '{other}'\n{USAGE_KEY}")),
        }
    }
    let dir = match dir {
        Some(d) => d,
        None => default_key_dir()?,
    };
    if let Some(why) = key_dir_refusal(&dir, root) {
        return Err(why);
    }
    let tool = ab::tool(root)?;
    let d = dir.to_string_lossy().into_owned();
    let v: Value = serde_json::from_str(
        tool_output(&tool, &["release-key", sub, "--dir", d.as_str()])?.trim(),
    )
    .map_err(|e| e.to_string())?;
    if sub == "check" {
        let id = v.get("id").and_then(Value::as_str).unwrap_or("?");
        let known = release_keys(&root.join(RELEASE_KEYS))?
            .iter()
            .any(|(k, _)| k == id);
        eprintln!(
            "release key {id} in {d}: the passphrase opens it; it is {}in {RELEASE_KEYS}/ of this checkout",
            if known { "" } else { "NOT " }
        );
        return Ok(());
    }
    let id = v.get("id").and_then(Value::as_str).unwrap_or("?");
    let pub_file = v.get("pub").and_then(Value::as_str).unwrap_or("?");
    for line in [
        format!("\nrelease key {id} made in {d}\n\nNext:"),
        "1. Back up the whole directory offline now (two USB drives kept apart; the".into(),
        "   passphrase on paper, apart from them): without the key and its passphrase no".into(),
        "   router installed from a release accepts another update (docs/release.md, \"Backup\")."
            .into(),
        "2. Put the public key in the repository by a PR (it is public; the private part never):"
            .into(),
        format!("     cp {pub_file} {RELEASE_KEYS}/"),
        "   From then on development images trust it as well, and `os release` signs with it."
            .into(),
    ] {
        eprintln!("{line}");
    }
    Ok(())
}

/// The `*.pub` files of the repository's release keys: each one the hex
/// Ed25519 public key, named by its id (`os check`).
pub fn release_keys(dir: &Path) -> Result<Vec<(String, String)>, String> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Ok(Vec::new());
    };
    let mut keys = Vec::new();
    for e in rd.flatten() {
        let p = e.path();
        let Some(name) = p.file_name().and_then(|n| n.to_str()).map(str::to_owned) else {
            continue;
        };
        let Some(id) = name.strip_suffix(".pub") else {
            if name != "README.md" {
                return Err(format!(
                    "{RELEASE_KEYS}/{name}: only <id>.pub files belong here"
                ));
            }
            continue;
        };
        let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        let public = text.trim();
        if public.len() != 64 || !public.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "{RELEASE_KEYS}/{name}: not an Ed25519 public key (64 hex digits)"
            ));
        }
        let want = key_id(public).ok_or("hex")?;
        if id != want {
            return Err(format!("{RELEASE_KEYS}/{name}: the key's id is {want}"));
        }
        keys.push((id.to_owned(), public.to_ascii_lowercase()));
    }
    keys.sort();
    Ok(keys)
}

/// `corerouter_sysupdate::package::key_id`: the first 8 bytes of the
/// SHA-256 of the raw public key, in hex.
fn key_id(public_hex: &str) -> Option<String> {
    let raw: Option<Vec<u8>> = (0..public_hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(public_hex.get(i..i + 2)?, 16).ok())
        .collect();
    let d = Sha256::digest(raw?);
    Some(d.iter().take(8).map(|b| format!("{b:02x}")).collect())
}

/// The directory of public keys the image trusts (`post-build.sh` copies
/// it to `/etc/corerouter/image-keys`), made afresh in `<top>/trust`:
/// - development: the signing key's (`signing_pub`) and the release keys;
/// - release: the release keys only, and the signing key must be one.
pub fn trust_dir(
    top: &Path,
    signing_pub: &Path,
    release_dir: &Path,
    release: bool,
) -> Result<PathBuf, String> {
    let released = release_keys(release_dir)?;
    let mut signing = Vec::new();
    for e in std::fs::read_dir(signing_pub)
        .map_err(|e| format!("{}: {e}", signing_pub.display()))?
        .flatten()
    {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "pub") {
            let id = p
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let text = std::fs::read_to_string(&p).map_err(|e| e.to_string())?;
            signing.push((id, text.trim().to_ascii_lowercase()));
        }
    }
    let mut keys = released.clone();
    if release {
        if released.is_empty() {
            return Err(format!(
                "no release public key in {RELEASE_KEYS}/: run `cargo xtask os release-key init` \
                 and commit its .pub first (docs/release.md)"
            ));
        }
        if let Some((id, _)) = signing.iter().find(|k| !released.contains(k)) {
            return Err(format!(
                "the signing key {id} is not one of the release keys in {RELEASE_KEYS}/"
            ));
        }
    } else {
        keys.extend(signing);
    }
    keys.sort();
    keys.dedup();
    let dir = top.join("trust");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for (id, public) in &keys {
        std::fs::write(dir.join(format!("{id}.pub")), format!("{public}\n"))
            .map_err(|e| e.to_string())?;
    }
    let ids: Vec<&str> = keys.iter().map(|(id, _)| id.as_str()).collect();
    eprintln!(
        "   image trusts {} key(s): {}{}",
        ids.len(),
        ids.join(" "),
        if release { " (release only)" } else { "" }
    );
    Ok(dir)
}

// --------------------------------------------------------------- release --

struct Opts {
    tag: String,
    key_dir: Option<PathBuf>,
    dry_run: bool,
    no_build: bool,
    repo: Option<String>,
    build_args: Vec<String>,
}

fn parse(args: &[String]) -> Result<Opts, String> {
    let mut o = Opts {
        tag: String::new(),
        key_dir: None,
        dry_run: false,
        no_build: false,
        repo: None,
        build_args: Vec::new(),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().cloned().ok_or(format!("{a} needs a value"));
        match a.as_str() {
            "--tag" => o.tag = val()?,
            "--key-dir" => o.key_dir = Some(PathBuf::from(val()?)),
            "--dry-run" => o.dry_run = true,
            "--no-build" => o.no_build = true,
            "--repo" => o.repo = Some(val()?),
            "--jobs" | "--top-jobs" => {
                let v = val()?;
                o.build_args.extend([a.clone(), v]);
            }
            other => return Err(format!("unknown argument '{other}'\n{USAGE}")),
        }
    }
    if o.tag.is_empty() {
        return Err(USAGE.into());
    }
    Ok(o)
}

/// `v0.2.0` → `0.2.0`, `v0.2.0-rc.1` → `0.2.0-rc.1`; the version before the
/// pre-release must be the workspace's (as the `.deb` of release.yml).
pub fn tag_version(tag: &str, workspace: &str) -> Result<String, String> {
    let v = tag
        .strip_prefix('v')
        .ok_or_else(|| format!("tag '{tag}': starts with v (v0.1.0)"))?;
    let ok = !v.is_empty()
        && v.len() <= 64
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if !ok {
        return Err(format!("tag '{tag}': only letters, digits, '.' and '-'"));
    }
    let base = v.split('-').next().unwrap_or(v);
    if base != workspace {
        return Err(format!(
            "tag {tag}: the workspace is {workspace} (bump [workspace.package] version first)"
        ));
    }
    Ok(v.to_owned())
}

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let o = Command::new("git")
        .args(args)
        .current_dir(root)
        .stderr(Stdio::null())
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !o.status.success() {
        return Err(format!("git {} failed", args.join(" ")));
    }
    Ok(String::from_utf8_lossy(&o.stdout).trim().to_owned())
}

fn tool_output(tool: &Path, args: &[&str]) -> Result<String, String> {
    let o = Command::new(tool)
        .args(args)
        .stderr(Stdio::inherit())
        .output()
        .map_err(|e| format!("{}: {e}", tool.display()))?;
    if !o.status.success() {
        return Err(format!("corerouter-image {}: failed", args.join(" ")));
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

fn gh(repo: Option<&str>, args: &[&str]) -> Result<String, String> {
    let mut cmd = Command::new("gh");
    cmd.args(args);
    if let Some(r) = repo {
        cmd.args(["--repo", r]);
    }
    let o = cmd
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("gh: {e} (install the GitHub CLI and `gh auth login`)"))?;
    if !o.status.success() {
        return Err(format!(
            "gh {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&o.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&o.stdout).into_owned())
}

/// The decrypted key, in a private directory on a tmpfs when there is one;
/// overwritten and removed when the release ends, failed or not.
struct TempKey {
    dir: PathBuf,
    file: PathBuf,
}

impl TempKey {
    fn new() -> Result<TempKey, String> {
        let base = match std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
            Some(r) => PathBuf::from(r),
            None => {
                eprintln!(
                    "   warning: no $XDG_RUNTIME_DIR: the decrypted key goes to {} for the build",
                    std::env::temp_dir().display()
                );
                std::env::temp_dir()
            }
        };
        let dir = base.join(format!("corerouter-release-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&dir)
                .map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let file = dir.join("release.pk8");
        Ok(TempKey { dir, file })
    }
}

impl Drop for TempKey {
    fn drop(&mut self) {
        if let Ok(m) = std::fs::metadata(&self.file) {
            let _ = std::fs::write(&self.file, vec![0u8; m.len() as usize]);
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The release build's directory: the development one's name with
/// `-release` (its own Buildroot output, ccache and keys), never inside
/// the repository.
fn release_top(root: &Path) -> Result<PathBuf, String> {
    let dev = out::resolve(root)?.dir;
    let top = PathBuf::from(format!("{}-release", dev.display()));
    let r = std::fs::canonicalize(root).map_err(|e| e.to_string())?;
    if resolve_partial(&top).starts_with(&r) {
        return Err(format!(
            "the release build would be inside the checkout ({}): move the build to the build \
             disk first (docs/os-image.md, \"Onde fica o build\")",
            top.display()
        ));
    }
    Ok(top)
}

/// The files of a release, as published: (name in the Release, file of the build).
fn assets(images: &Path, version: &str) -> Vec<(String, PathBuf)> {
    [
        ("corerouter.crpkg", format!("corerouter-{version}.crpkg")),
        (
            "corerouter-install.iso",
            format!("corerouter-{version}-install.iso"),
        ),
        ("corerouter.qcow2", format!("corerouter-{version}.qcow2")),
        ("corerouter.ova", format!("corerouter-{version}.ova")),
    ]
    .into_iter()
    .map(|(f, name)| (name, images.join(f)))
    .collect()
}

/// `SHA256SUMS` of the Release: the lines already there (the `.deb` of the
/// workflow) without the names this run writes, then ours, sorted by name.
pub fn merge_sums(existing: &str, ours: &[(String, String)]) -> String {
    let mut lines: Vec<(String, String)> = existing
        .lines()
        .filter_map(|l| {
            let (hash, name) = l.split_once("  ")?;
            let name = name.trim_start_matches('*');
            (!ours.iter().any(|(n, _)| n == name)).then(|| (name.to_owned(), hash.to_owned()))
        })
        .collect();
    lines.extend(ours.iter().map(|(n, h)| (n.clone(), h.clone())));
    lines.sort();
    lines.iter().map(|(n, h)| format!("{h}  {n}\n")).collect()
}

pub fn release(root: &Path, args: &[String]) -> Result<(), String> {
    let o = parse(args)?;
    let version = tag_version(&o.tag, &super::workspace_version(root))?;
    let channel = if version.contains('-') {
        "testing"
    } else {
        "stable"
    };

    // 1. The checkout is the tag, with nothing else in it.
    let tag_ref = format!("refs/tags/{}^{{commit}}", o.tag);
    let tag_commit = git(root, &["rev-parse", "--verify", "--quiet", &tag_ref]).map_err(|_| {
        format!(
            "no tag {} here: create and push it first (docs/release.md); this command never makes one",
            o.tag
        )
    })?;
    let head = git(root, &["rev-parse", "HEAD"])?;
    if head != tag_commit {
        return Err(format!(
            "the checkout is at {}, the tag {} at {}: check out the tag \
             (git worktree add /srv/build/release-src-{tag} {tag})",
            head.get(..12).unwrap_or(&head),
            o.tag,
            tag_commit.get(..12).unwrap_or(&tag_commit),
            tag = o.tag
        ));
    }
    let dirty = git(root, &["status", "--porcelain"])?;
    if !dirty.is_empty() {
        return Err(format!(
            "the checkout has changes or untracked files: a release builds the tag and nothing else\n{dirty}"
        ));
    }
    match git(
        root,
        &[
            "ls-remote",
            "--tags",
            "origin",
            &format!("refs/tags/{}", o.tag),
        ],
    ) {
        Ok(remote) if remote.is_empty() => {
            let msg = format!(
                "the tag {} is not on origin (git push origin {})",
                o.tag, o.tag
            );
            if !o.dry_run {
                return Err(msg);
            }
            eprintln!("   warning: {msg}");
        }
        Ok(_) => {}
        Err(e) if o.dry_run => eprintln!("   warning: {e}"),
        Err(e) => return Err(e),
    }

    // 2. The draft the release workflow made (never a published one).
    let repo = o.repo.as_deref();
    let draft = gh(
        repo,
        &["release", "view", &o.tag, "--json", "isDraft,tagName"],
    );
    match &draft {
        Ok(j) => {
            let v: Value = serde_json::from_str(j.trim()).map_err(|e| e.to_string())?;
            if v.get("isDraft").and_then(Value::as_bool) != Some(true) {
                return Err(format!(
                    "the Release {} is already published: this command only adds to a draft",
                    o.tag
                ));
            }
        }
        Err(e) if o.dry_run => eprintln!("   warning (dry run): {e}"),
        Err(e) => {
            return Err(format!(
                "{e}\nno draft Release for {}: the release workflow makes it when the tag is pushed",
                o.tag
            ));
        }
    }

    // 3. The key: release keys in the repository, the private one outside.
    let key_dir = match o.key_dir.clone() {
        Some(d) => d,
        None => default_key_dir()?,
    };
    if let Some(why) = key_dir_refusal(&key_dir, root) {
        return Err(why);
    }
    if !key_dir.join(KEY_FILE).is_file() {
        return Err(format!(
            "{}: no release key (cargo xtask os release-key init, or --key-dir)",
            key_dir.join(KEY_FILE).display()
        ));
    }
    let release_dir = root.join(RELEASE_KEYS);
    let released = release_keys(&release_dir)?;
    if released.is_empty() {
        return Err(format!(
            "no release public key in {RELEASE_KEYS}/ at this tag (docs/release.md)"
        ));
    }
    let tool = ab::tool(root)?;
    let top = release_top(root)?;
    let images = top.join("build/images");

    // 4. Build (or reuse this tag's build), signed with the release key.
    if o.no_build {
        eprintln!("   --no-build: the release build in {}", top.display());
    } else {
        let tmp = TempKey::new()?;
        let kd = key_dir.to_string_lossy().into_owned();
        let out_s = tmp.file.to_string_lossy().into_owned();
        let v: Value = serde_json::from_str(
            tool_output(
                &tool,
                &[
                    "release-key",
                    "decrypt",
                    "--dir",
                    kd.as_str(),
                    "--out",
                    out_s.as_str(),
                ],
            )?
            .trim(),
        )
        .map_err(|e| e.to_string())?;
        let id = v.get("id").and_then(Value::as_str).unwrap_or("");
        if !released.iter().any(|(k, _)| k == id) {
            return Err(format!(
                "the key in {} ({id}) is not one of {RELEASE_KEYS}/ at this tag",
                key_dir.display()
            ));
        }
        eprintln!("   release key {id}: ok; build in {}", top.display());
        std::fs::create_dir_all(&top).map_err(|e| format!("{}: {e}", top.display()))?;
        super::build_with(
            root,
            &o.build_args,
            Some(&ReleaseBuild {
                top: top.clone(),
                key: tmp.file.clone(),
                version: version.clone(),
                channel: channel.into(),
            }),
        )?;
        drop(tmp);
    }

    // 5. What came out is this tag, signed by a release key, trusting only those.
    let pkg = images.join("corerouter.crpkg");
    let pkg_s = pkg.to_string_lossy().into_owned();
    let m: Value = serde_json::from_str(tool_output(&tool, &["info", pkg_s.as_str()])?.trim())
        .map_err(|e| e.to_string())?;
    let commit = git(root, &["rev-parse", "--short=12", "HEAD"])?;
    for (field, want) in [
        ("version", version.as_str()),
        ("commit", commit.as_str()),
        ("channel", channel),
    ] {
        if m.get(field).and_then(Value::as_str) != Some(want) {
            return Err(format!(
                "{}: {field} {}, expected {want} (build again without --no-build)",
                pkg.display(),
                m.get(field).unwrap_or(&Value::Null)
            ));
        }
    }
    let rd = release_dir.to_string_lossy().into_owned();
    tool_output(&tool, &["verify", pkg_s.as_str(), "--keys", rd.as_str()])
        .map_err(|_| format!("{}: not signed by a release key", pkg.display()))?;
    let trusted = release_keys(&top.join("build/target/etc/corerouter/image-keys"))?;
    if trusted != released {
        return Err(format!(
            "the image trusts {:?}, expected only the release keys {:?}",
            trusted.iter().map(|k| &k.0).collect::<Vec<_>>(),
            released.iter().map(|k| &k.0).collect::<Vec<_>>()
        ));
    }

    // 6. The files with their published names, and the SHA-256 sums.
    let stage = top.join("release").join(&o.tag);
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage).map_err(|e| format!("{}: {e}", stage.display()))?;
    let mut sums = Vec::new();
    let mut files = Vec::new();
    for (name, src) in assets(&images, &version) {
        if !src.is_file() {
            return Err(format!(
                "{}: missing (a release needs the whole build: qemu-img for the VM images)",
                src.display()
            ));
        }
        let dst = stage.join(&name);
        if std::fs::hard_link(&src, &dst).is_err() {
            std::fs::copy(&src, &dst).map_err(|e| format!("{}: {e}", dst.display()))?;
        }
        sums.push((name, sha256_file(&dst)?));
        files.push(dst);
    }
    let existing = if o.dry_run && draft.is_err() {
        String::new()
    } else {
        let dl = stage.join("SHA256SUMS.draft");
        let dls = stage.to_string_lossy().into_owned();
        match gh(
            repo,
            &[
                "release",
                "download",
                &o.tag,
                "--pattern",
                "SHA256SUMS",
                "--dir",
                dls.as_str(),
                "--clobber",
            ],
        ) {
            Ok(_) => {
                let p = stage.join("SHA256SUMS");
                let t = std::fs::read_to_string(&p).unwrap_or_default();
                let _ = std::fs::rename(&p, &dl);
                t
            }
            Err(e) => {
                eprintln!("   (no SHA256SUMS in the draft yet: {e})");
                String::new()
            }
        }
    };
    let sums_file = stage.join("SHA256SUMS");
    let text = merge_sums(&existing, &sums);
    std::fs::write(&sums_file, &text).map_err(|e| e.to_string())?;
    files.push(sums_file);
    eprintln!("\n{} {version} ({channel}, commit {commit}):", o.tag);
    for (name, hash) in &sums {
        let len = std::fs::metadata(stage.join(name))
            .map(|m| m.len())
            .unwrap_or(0);
        eprintln!(
            "  {name:<40} {:>8.1} MiB  sha256 {hash}",
            len as f64 / 1048576.0
        );
    }

    // 7. Upload to the draft (replacing this run's files of an earlier try).
    let paths: Vec<String> = files
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let mut up = vec!["release", "upload", o.tag.as_str()];
    up.extend(paths.iter().map(String::as_str));
    up.push("--clobber");
    if o.dry_run {
        eprintln!(
            "\n--dry-run: nothing uploaded. Would run:\n  gh {}{}",
            up.join(" "),
            repo.map(|r| format!(" --repo {r}")).unwrap_or_default()
        );
        return Ok(());
    }
    gh(repo, &up)?;
    eprintln!(
        "\nuploaded to the draft Release {}. Review it on GitHub (Releases → Edit) and publish \
         it there: this command never publishes.",
        o.tag
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_version_follows_the_workspace() {
        assert_eq!(tag_version("v0.1.0", "0.1.0").unwrap(), "0.1.0");
        assert_eq!(tag_version("v0.1.0-rc.1", "0.1.0").unwrap(), "0.1.0-rc.1");
        assert!(tag_version("0.1.0", "0.1.0").is_err());
        assert!(tag_version("v0.2.0", "0.1.0").unwrap_err().contains("bump"));
        assert!(tag_version("v0.1.0+x", "0.1.0").is_err());
        assert!(tag_version("v0.1.0-$(rm)", "0.1.0").is_err());
    }

    #[test]
    fn sums_keep_the_deb_and_replace_ours() {
        let existing = "aa  corerouter-gui_0.1.0_amd64.deb\nbb  corerouter-0.1.0.crpkg\n";
        let ours = vec![
            ("corerouter-0.1.0.crpkg".to_owned(), "cc".to_owned()),
            ("corerouter-0.1.0.ova".to_owned(), "dd".to_owned()),
        ];
        assert_eq!(
            merge_sums(existing, &ours),
            "cc  corerouter-0.1.0.crpkg\ndd  corerouter-0.1.0.ova\naa  corerouter-gui_0.1.0_amd64.deb\n"
        );
    }

    #[test]
    fn key_dir_outside_repo_and_build_disk() {
        let root = std::env::current_dir().unwrap();
        assert!(key_dir_refusal(&root.join("os/out/k"), &root).is_some());
        assert!(key_dir_refusal(Path::new("/srv/build/k"), &root).is_some());
        assert!(key_dir_refusal(Path::new("/nonexistent-cr/release-key"), &root).is_none());
    }

    fn write_pub(dir: &Path, public: &str) -> String {
        let id = key_id(public).unwrap();
        std::fs::write(dir.join(format!("{id}.pub")), format!("{public}\n")).unwrap();
        id
    }

    #[test]
    fn trust_dev_has_both_release_only_release() {
        let t = std::env::temp_dir().join(format!("cr-trust-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        let (rel, dev) = (t.join("release"), t.join("dev"));
        std::fs::create_dir_all(&rel).unwrap();
        std::fs::create_dir_all(&dev).unwrap();
        // No release key yet: the development image is what it was.
        let dev_id = write_pub(&dev, &"11".repeat(32));
        let d = trust_dir(&t, &dev, &rel, false).unwrap();
        assert_eq!(release_keys(&d).unwrap().len(), 1);
        assert!(
            trust_dir(&t, &dev, &rel, true)
                .unwrap_err()
                .contains("no release")
        );
        let rel_id = write_pub(&rel, &"22".repeat(32));
        let d = trust_dir(&t, &dev, &rel, false).unwrap();
        let ids: Vec<String> = release_keys(&d).unwrap().into_iter().map(|k| k.0).collect();
        assert!(ids.contains(&dev_id) && ids.contains(&rel_id));
        // A release build signed by the dev key: refused.
        assert!(
            trust_dir(&t, &dev, &rel, true)
                .unwrap_err()
                .contains("not one of")
        );
        let signer = t.join("signer");
        std::fs::create_dir_all(&signer).unwrap();
        write_pub(&signer, &"22".repeat(32));
        let d = trust_dir(&t, &signer, &rel, true).unwrap();
        let ids: Vec<String> = release_keys(&d).unwrap().into_iter().map(|k| k.0).collect();
        assert_eq!(ids, vec![rel_id]);
        std::fs::remove_dir_all(&t).unwrap();
    }

    #[test]
    fn release_keys_are_checked() {
        let t = std::env::temp_dir().join(format!("cr-relkeys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&t);
        std::fs::create_dir_all(&t).unwrap();
        assert!(release_keys(&t.join("missing")).unwrap().is_empty());
        std::fs::write(t.join("README.md"), "x").unwrap();
        std::fs::write(t.join("0000000000000000.pub"), "33".repeat(32)).unwrap();
        assert!(release_keys(&t).unwrap_err().contains("id is"));
        std::fs::remove_file(t.join("0000000000000000.pub")).unwrap();
        std::fs::write(t.join("x.pub"), "zz").unwrap();
        assert!(release_keys(&t).unwrap_err().contains("64 hex"));
        std::fs::remove_file(t.join("x.pub")).unwrap();
        std::fs::write(t.join("dev-image-key.pk8"), "x").unwrap();
        assert!(release_keys(&t).unwrap_err().contains("only <id>.pub"));
        std::fs::remove_dir_all(&t).unwrap();
    }
}

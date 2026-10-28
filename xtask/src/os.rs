//! G1.6a: `cargo xtask os <build|boot-test|check>` — the CoreRouter OS image
//! (Buildroot external tree in `os/`, `docs/os-image.md`).
//!
//! - `build` downloads the pinned Buildroot once (hash checked), configures
//!   it with `os/configs/corerouter_x86_64_defconfig`, checks the kernel
//!   tarball against `os/patches/linux/linux.hash` (Buildroot would accept a
//!   custom kernel with no hash file at all), rebuilds the Rust binaries and the image,
//!   and checks that every `=y` of the kernel fragment survived.
//! - `boot-test` boots `disk.img` in QEMU as the user (KVM when `/dev/kvm`
//!   is usable, TCG otherwise), waits for corerouter-init's `ready:` line and
//!   pings the daemon over the TLS control channel from the host.
//! - `check` (also a unit test, so `cargo xtask ci` runs it without
//!   downloading anything) validates the configuration files.
//! - G1.6c: `build` also makes the installer ISO (post-image.sh), the VM
//!   images (`corerouter.qcow2`, `corerouter.ova`, with the host's
//!   `qemu-img`) and checks that every ELF of the image finds its
//!   libraries; `install-test` runs the installer and the VM images in
//!   QEMU (`os/install.rs`).
//! - G1.6k: `build` applies `os/buildroot-patches/*.patch` to the extracted
//!   Buildroot tree (package versions newer than the LTS branch ships, FRR
//!   10.7.1) and extracts it again when those patches change; `frr-test`
//!   runs OSPF/SR/LDP/BFD between two guests of the image (`os/frr.rs`).

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::Outcome;
use crate::vm_lab::{download, sha256_file};

mod ab;
mod frr;
mod install;

const DEFCONFIG: &str = "corerouter_x86_64_defconfig";
/// Free space the build wants before it starts (cold build: ~8 GB in
/// `os/out`, **medido**; the rest is headroom for parallel sessions).
const MIN_FREE_GB: u64 = 25;
/// Kernel options the router cannot run without: `check` fails when the
/// fragment loses one, `build` when the configured kernel does.
const REQUIRED_KERNEL: &[&str] = &[
    "CONFIG_BPF_SYSCALL",
    "CONFIG_BPF_JIT",
    "CONFIG_DEBUG_INFO_BTF",
    "CONFIG_XDP_SOCKETS",
    "CONFIG_NF_TABLES",
    "CONFIG_NF_TABLES_INET",
    "CONFIG_NFT_NAT",
    "CONFIG_NF_CONNTRACK",
    "CONFIG_NET_VRF",
    "CONFIG_MPLS_ROUTING",
    "CONFIG_MPLS_IPTUNNEL",
    "CONFIG_BONDING",
    "CONFIG_VLAN_8021Q",
    "CONFIG_BRIDGE_VLAN_FILTERING",
    "CONFIG_PPPOE",
    "CONFIG_IXGBE",
    "CONFIG_I40E",
    "CONFIG_ICE",
    "CONFIG_MLX5_CORE_EN",
    "CONFIG_VIRTIO_NET",
    "CONFIG_VIRTIO_BLK",
    "CONFIG_SQUASHFS",
    "CONFIG_SQUASHFS_ZSTD",
    "CONFIG_EXT4_FS",
    "CONFIG_EFI_STUB",
    "CONFIG_DEVTMPFS_MOUNT",
    "CONFIG_DM_VERITY",
    "CONFIG_DM_INIT",
    "CONFIG_EFIVAR_FS",
    // G1.6c: the installer's media (CD, USB stick), its unattended flag,
    // the VMware/VirtualBox disks and ports.
    "CONFIG_BLK_DEV_SR",
    "CONFIG_USB_STORAGE",
    "CONFIG_USB_XHCI_HCD",
    "CONFIG_FW_CFG_SYSFS",
    "CONFIG_ATA_PIIX",
    "CONFIG_VMXNET3",
];
/// Buildroot options the image's design rests on (docs/os-image.md).
const REQUIRED_BR2: &[&str] = &[
    "BR2_INIT_NONE=y",
    "BR2_TARGET_ROOTFS_SQUASHFS=y",
    "BR2_REPRODUCIBLE=y",
    "BR2_DOWNLOAD_FORCE_CHECK_HASHES=y",
    "BR2_PER_PACKAGE_DIRECTORIES=y",
    "BR2_PACKAGE_COREROUTER=y",
    "BR2_PACKAGE_NFTABLES=y",
    "# BR2_TARGET_ENABLE_ROOT_LOGIN is not set",
    "BR2_PACKAGE_FRR=y",
    "BR2_PACKAGE_LIBCAP=y",
    "BR2_PACKAGE_COREROUTER_INSTALLER=y",
];
/// What the installer kernel's fragment must say (G1.6c).
const INSTALLER_KERNEL: &[&str] = &[
    "CONFIG_CMDLINE=\"console=tty0 console=ttyS0,115200 corerouter.mode=install panic=10 quiet\"",
    "CONFIG_INITRAMFS_COMPRESSION_ZSTD=y",
    "# CONFIG_DEBUG_INFO_BTF is not set",
];
/// The installer's boot image (El Torito counts 16-bit 512-byte sectors).
const MAX_BOOT_IMAGE: u64 = 65535 * 512;
const INIT_PATH: &str = "/usr/sbin/corerouter-init";
/// eth0 on QEMU's user network (slirp: guest 10.0.2.15, gateway 10.0.2.2),
/// set by the kernel before init (`CONFIG_IP_PNP`).
const GUEST_IP_ARG: &str = "ip=10.0.2.15::10.0.2.2:255.255.255.0::eth0:off";
/// The daemon's TLS control port inside the image (corerouter-init's plan).
const GUEST_TLS_PORT: u16 = 8729;

const USAGE: &str = "usage: cargo xtask os <build [--jobs N] [--top-jobs N] [--key PKCS8] [--channel C]|boot-test [--efi] [--tcg] [--timeout S] [--append ARGS] [--keep-config]|ab-test [--tcg] [--scenario update|no-confirm|bad-signature|bad-param]|install-test [--tcg]|frr-test [--tcg]|package --out FILE [--version V] [--build N] [--channel C] [--key PKCS8]|check>";

pub fn main(root: &Path, args: &[String]) -> Outcome {
    let (sub, rest) = match args.split_first() {
        Some((s, r)) => (s.as_str(), r),
        None => return Outcome::Fail(USAGE.into()),
    };
    let res = match sub {
        "build" => build(root, rest),
        "boot-test" => boot_test(root, rest),
        "ab-test" => images_dir(root).and_then(|i| ab::ab_test(root, &i, rest)),
        "install-test" => images_dir(root).and_then(|i| install::install_test(root, &i, rest)),
        "frr-test" => images_dir(root).and_then(|i| frr::frr_test(root, &i, rest)),
        "package" => images_dir(root).and_then(|i| package_cmd(root, &i, rest)),
        "check" => check(&root.join("os")).map(|n| eprintln!("ok: os/ configuration ({n} checks)")),
        "-h" | "--help" => {
            eprintln!("{USAGE}");
            Ok(())
        }
        other => Err(format!("unknown subcommand '{other}'\n{USAGE}")),
    };
    match res {
        Ok(()) => Outcome::Ok,
        Err(e) => Outcome::Fail(e),
    }
}

/// `os package`: another package of the sealed build (`corerouter-image package`).
fn package_cmd(root: &Path, images: &Path, args: &[String]) -> Result<(), String> {
    let tool = ab::tool(root)?;
    let mut cmd = Command::new(&tool);
    cmd.arg("package").arg("--images").arg(images);
    if !args.iter().any(|a| a == "--key") {
        cmd.arg("--keys").arg(root.join("os/out/keys"));
    }
    let st = cmd
        .args(args)
        .status()
        .map_err(|e| format!("{}: {e}", tool.display()))?;
    if st.success() {
        Ok(())
    } else {
        Err(format!("corerouter-image package: {st}"))
    }
}

fn images_dir(root: &Path) -> Result<PathBuf, String> {
    let lock = parse_lock(
        &std::fs::read_to_string(root.join("os/buildroot.lock")).map_err(|e| e.to_string())?,
    )?;
    Ok(dirs(root, &lock).out.join("images"))
}

/// `pub const FORMAT_VERSION: u32 = N;` of the model (the configuration
/// schema the image's daemon writes), read from the source.
fn config_format(root: &Path) -> Result<u32, String> {
    let src = std::fs::read_to_string(root.join("crates/model/src/persist.rs"))
        .map_err(|e| e.to_string())?;
    src.lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("pub const FORMAT_VERSION: u32 = ")?
                .strip_suffix(';')?
                .parse()
                .ok()
        })
        .ok_or_else(|| "crates/model/src/persist.rs: no FORMAT_VERSION".into())
}

/// The workspace version (`[workspace.package] version`).
fn workspace_version(root: &Path) -> String {
    std::fs::read_to_string(root.join("Cargo.toml"))
        .ok()
        .and_then(|t| {
            t.lines()
                .skip_while(|l| l.trim() != "[workspace.package]")
                .find_map(|l| {
                    l.trim()
                        .strip_prefix("version = ")
                        .map(|v| v.trim_matches('"').to_owned())
                })
        })
        .unwrap_or_else(|| "0.0.0".into())
}

/// The commit time of HEAD: orders package versions (`build`), reproducible.
fn git_time(root: &Path) -> u64 {
    Command::new("git")
        .args(["log", "-1", "--format=%ct"])
        .current_dir(root)
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
        .unwrap_or(0)
}

// ---------------------------------------------------------------- config --

struct Lock {
    version: String,
    url: String,
    sha256: String,
}

fn parse_lock(text: &str) -> Result<Lock, String> {
    let get = |key: &str| {
        text.lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .find_map(|l| {
                let (k, v) = l.split_once('=')?;
                (k.trim() == key).then(|| v.trim().to_owned())
            })
            .ok_or_else(|| format!("os/buildroot.lock: no '{key} = …'"))
    };
    let lock = Lock {
        version: get("version")?,
        url: get("url")?,
        sha256: get("sha256")?,
    };
    if !is_sha256(&lock.sha256) {
        return Err("os/buildroot.lock: sha256 is not 64 hex digits".into());
    }
    if !lock.url.starts_with("https://") || !lock.url.contains(&lock.version) {
        return Err("os/buildroot.lock: url must be https and name the version".into());
    }
    Ok(lock)
}

fn is_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// `KEY="value"` → `value` in a defconfig or kernel config.
fn config_value<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    text.lines().find_map(|l| {
        let v = l.strip_prefix(key)?.strip_prefix('=')?;
        Some(v.trim_matches('"'))
    })
}

fn kernel_version(defconfig: &str) -> Result<String, String> {
    config_value(defconfig, "BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE")
        .map(str::to_owned)
        .ok_or_else(|| "defconfig: no BR2_LINUX_KERNEL_CUSTOM_VERSION_VALUE".into())
}

/// The expected SHA-256 of `linux-<version>.tar.xz` from `linux.hash`.
fn kernel_hash(hash_file: &str, version: &str) -> Option<String> {
    let name = format!("linux-{version}.tar.xz");
    hash_file.lines().find_map(|l| {
        let mut w = l.split_whitespace();
        (w.next()? == "sha256").then_some(())?;
        let h = w.next()?;
        (w.next()? == name && is_sha256(h)).then(|| h.to_owned())
    })
}

/// The `=y` symbols of a kernel config fragment.
fn fragment_symbols(fragment: &str) -> Vec<&str> {
    fragment
        .lines()
        .filter_map(|l| l.strip_suffix("=y"))
        .filter(|s| s.starts_with("CONFIG_"))
        .collect()
}

/// `partition <name> { … partition-uuid = "<uuid>" … }` in genimage.cfg.
fn genimage_partuuid(cfg: &str, partition: &str) -> Option<String> {
    let start = cfg.find(&format!("partition {partition} {{"))?;
    let body = cfg.get(start..)?;
    let end = body.find('}')?;
    body.get(..end)?.lines().find_map(|l| {
        let v = l
            .trim()
            .strip_prefix("partition-uuid")?
            .trim()
            .strip_prefix('=')?;
        Some(v.trim().trim_matches('"').to_owned())
    })
}

/// Static checks of `os/` (no network, no Buildroot tree): returns how many
/// passed.
pub fn check(os: &Path) -> Result<usize, String> {
    let read =
        |rel: &str| std::fs::read_to_string(os.join(rel)).map_err(|e| format!("os/{rel}: {e}"));
    let mut n = 0;
    parse_lock(&read("buildroot.lock")?)?;
    n += 1;
    let defconfig = read(&format!("configs/{DEFCONFIG}"))?;
    for want in REQUIRED_BR2 {
        if !defconfig.lines().any(|l| l == *want) {
            return Err(format!("defconfig: missing '{want}' (docs/os-image.md)"));
        }
        n += 1;
    }
    // Every file of this tree the defconfig names exists.
    for (i, _) in defconfig.match_indices("$(BR2_EXTERNAL_COREROUTER_PATH)/") {
        let rest = defconfig
            .get(i + "$(BR2_EXTERNAL_COREROUTER_PATH)/".len()..)
            .unwrap_or("");
        let rel: String = rest
            .chars()
            .take_while(|c| !matches!(c, '"' | ' ' | '\n'))
            .collect();
        // dl/ and out/ are made by the build.
        if rel.starts_with("dl") || rel.starts_with("out") {
            continue;
        }
        if !os.join(&rel).exists() {
            return Err(format!("defconfig names os/{rel}, which does not exist"));
        }
        n += 1;
    }
    let version = kernel_version(&defconfig)?;
    if kernel_hash(&read("patches/linux/linux.hash")?, &version).is_none() {
        return Err(format!(
            "os/patches/linux/linux.hash: no sha256 for linux-{version}.tar.xz"
        ));
    }
    n += 1;
    let fragment = read("board/x86_64/linux.fragment")?;
    let syms = fragment_symbols(&fragment);
    for want in REQUIRED_KERNEL {
        if !syms.contains(want) {
            return Err(format!("linux.fragment: {want}=y is required"));
        }
        n += 1;
    }
    let cmdline =
        config_value(&fragment, "CONFIG_CMDLINE").ok_or("linux.fragment: no CONFIG_CMDLINE")?;
    let root_uuid = cmdline
        .split_whitespace()
        .find_map(|w| w.strip_prefix("root=PARTUUID="))
        .ok_or("CONFIG_CMDLINE: no root=PARTUUID=")?;
    let genimage = read("board/x86_64/genimage.cfg")?;
    let a = genimage_partuuid(&genimage, "rootfs-a")
        .ok_or("genimage.cfg: rootfs-a has no partition-uuid")?;
    if a != root_uuid {
        return Err(format!(
            "CONFIG_CMDLINE root=PARTUUID={root_uuid} is not rootfs-a ({a}) in genimage.cfg"
        ));
    }
    n += 1;
    // The A/B boot entries are written after this line
    // (`corerouter_sysupdate::BUILTIN_CMDLINE`, read from its source: the
    // xtask uses no workspace crate).
    let sysupdate = std::fs::read_to_string(os.join("../crates/sysupdate/src/lib.rs"))
        .map_err(|e| format!("crates/sysupdate/src/lib.rs: {e}"))?;
    let builtin = sysupdate
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("pub const BUILTIN_CMDLINE: &str = \"")?
                .strip_suffix("\";")
        })
        .ok_or("crates/sysupdate/src/lib.rs: no BUILTIN_CMDLINE")?;
    if cmdline != builtin {
        return Err(format!(
            "CONFIG_CMDLINE differs from corerouter_sysupdate::BUILTIN_CMDLINE (the A/B boot entries are written after it): '{cmdline}'"
        ));
    }
    n += 1;
    if !genimage.contains("image = \"rootfs.img\"") {
        return Err(
            "genimage.cfg: rootfs-a must be rootfs.img (squashfs + dm-verity tree, `corerouter-image seal`)"
                .into(),
        );
    }
    n += 1;
    if !cmdline
        .split_whitespace()
        .any(|w| w == format!("init={INIT_PATH}"))
    {
        return Err(format!("CONFIG_CMDLINE: needs init={INIT_PATH}"));
    }
    if !read("package/corerouter/corerouter.mk")?.contains(&format!("$(TARGET_DIR){INIT_PATH}")) {
        return Err(format!("corerouter.mk does not install {INIT_PATH}"));
    }
    if !genimage.contains("label = \"config\"") || !genimage.contains("partition config {") {
        return Err(
            "genimage.cfg: the config partition (label config) is what corerouter-init mounts"
                .into(),
        );
    }
    n += 2;
    for script in ["board/x86_64/post-build.sh", "board/x86_64/post-image.sh"] {
        if !is_executable(&os.join(script)) {
            return Err(format!("os/{script} must be executable"));
        }
        n += 1;
    }
    n += check_installer(os, &genimage, &version)?;
    let (patches, _) = buildroot_patches(os)?;
    for p in &patches {
        let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
        let files: Vec<&str> = text
            .lines()
            .filter_map(|l| l.strip_prefix("+++ "))
            .collect();
        if files.is_empty() {
            return Err(format!("{}: patches no file", p.display()));
        }
        // Package recipes only: the build system itself stays the pinned one.
        if let Some(f) = files.iter().find(|f| !f.starts_with("b/package/")) {
            return Err(format!(
                "{}: patches {f}, outside Buildroot's package/",
                p.display()
            ));
        }
        n += 1;
    }
    Ok(n)
}

/// G1.6k: the patches `build` applies to the extracted Buildroot tree
/// (`os/buildroot-patches/*.patch`, in name order) and one hash over their
/// names and contents, which tells a tree patched with other files apart.
fn buildroot_patches(os: &Path) -> Result<(Vec<PathBuf>, String), String> {
    let dir = os.join("buildroot-patches");
    let mut patches: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "patch"))
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(format!("{}: {e}", dir.display())),
    };
    patches.sort();
    let mut hasher = Sha256::new();
    for p in &patches {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        hasher.update(name.as_bytes());
        hasher.update([0]);
        hasher.update(std::fs::read(p).map_err(|e| format!("{}: {e}", p.display()))?);
        hasher.update([0]);
    }
    let hash = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    Ok((patches, hash))
}

/// G1.6c: the installer's kernel, boot image and payload stay consistent.
fn check_installer(os: &Path, genimage: &str, version: &str) -> Result<usize, String> {
    let read =
        |rel: &str| std::fs::read_to_string(os.join(rel)).map_err(|e| format!("os/{rel}: {e}"));
    let mut n = 0;
    let frag = read("board/x86_64/installer.fragment")?;
    for want in INSTALLER_KERNEL {
        if !frag.lines().any(|l| l == *want) {
            return Err(format!("installer.fragment: missing '{want}'"));
        }
        n += 1;
    }
    if frag
        .lines()
        .any(|l| !l.starts_with('#') && l.contains("root="))
    {
        return Err("installer.fragment: the installer runs from its initramfs (no root=)".into());
    }
    // The same kernel tarball as the image, with the same hash.
    let main = kernel_hash(&read("patches/linux/linux.hash")?, version);
    let inst = kernel_hash(
        &read("package/corerouter-installer/corerouter-installer.hash")?,
        version,
    );
    if main.is_none() || main != inst {
        return Err(
            "corerouter-installer.hash must have the kernel tarball's hash from linux.hash".into(),
        );
    }
    n += 1;
    let mk = read("package/corerouter-installer/corerouter-installer.mk")?;
    if !mk.contains("COREROUTER_INSTALLER_DL_SUBDIR = linux") {
        return Err(
            "corerouter-installer.mk: share the kernel download (DL_SUBDIR = linux)".into(),
        );
    }
    n += 1;
    // The boot image: present, the installer kernel inside, under El
    // Torito's limit; config.ext4 kept for the ISO.
    let start = genimage
        .find("image efiboot.vfat {")
        .ok_or("genimage.cfg: no efiboot.vfat (the installer's boot image)")?;
    let body = genimage.get(start..).unwrap_or("");
    if !body.contains("image = \"installer/EFI\"") {
        return Err("genimage.cfg: efiboot.vfat must hold installer/EFI".into());
    }
    let size = body
        .lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("size = ")?
                .strip_suffix('M')?
                .parse::<u64>()
                .ok()
        })
        .ok_or("genimage.cfg: efiboot.vfat needs a size in M")?;
    if size << 20 > MAX_BOOT_IMAGE {
        return Err(format!(
            "genimage.cfg: efiboot.vfat of {size} MiB is over El Torito's {MAX_BOOT_IMAGE} bytes"
        ));
    }
    let cfg_start = genimage.find("image config.ext4 {").unwrap_or(0);
    let cfg_body = genimage.get(cfg_start..).unwrap_or("");
    let cfg_end = cfg_body.find("\n}").unwrap_or(cfg_body.len());
    if cfg_body
        .get(..cfg_end)
        .unwrap_or("")
        .contains("temporary = true")
    {
        return Err("genimage.cfg: config.ext4 must be kept (the ISO carries it)".into());
    }
    if !read("board/x86_64/post-image.sh")?.contains("installer \"$BINARIES_DIR\"") {
        return Err("post-image.sh: corerouter-image installer makes the ISO".into());
    }
    n += 3;
    Ok(n)
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(p: &Path) -> bool {
    p.exists()
}

// ----------------------------------------------------------------- build --

struct Dirs {
    os: PathBuf,
    buildroot: PathBuf,
    /// Buildroot's `O=`.
    out: PathBuf,
}

fn dirs(root: &Path, lock: &Lock) -> Dirs {
    let os = root.join("os");
    Dirs {
        buildroot: os.join("out").join(format!("buildroot-{}", lock.version)),
        out: os.join("out").join("build"),
        os,
    }
}

fn build(root: &Path, args: &[String]) -> Result<(), String> {
    let mut jobs: Option<String> = None;
    let mut top_jobs: Option<String> = None;
    let mut key: Option<PathBuf> = None;
    let mut channel = "development".to_owned();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--jobs" => jobs = Some(it.next().ok_or("--jobs needs a number")?.clone()),
            "--top-jobs" => top_jobs = Some(it.next().ok_or("--top-jobs needs a number")?.clone()),
            "--key" => key = Some(PathBuf::from(it.next().ok_or("--key needs a file")?)),
            "--channel" => channel = it.next().ok_or("--channel needs a name")?.clone(),
            other => return Err(format!("unknown argument '{other}'\n{USAGE}")),
        }
    }
    let started = Instant::now();
    check(&root.join("os"))?;
    let lock = parse_lock(
        &std::fs::read_to_string(root.join("os/buildroot.lock")).map_err(|e| e.to_string())?,
    )?;
    let d = dirs(root, &lock);
    std::fs::create_dir_all(d.os.join("dl")).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(d.os.join("out")).map_err(|e| e.to_string())?;
    let free = free_gb(&d.os.join("out"))?;
    if free < MIN_FREE_GB {
        return Err(format!(
            "only {free} GB free under os/out; the build wants {MIN_FREE_GB} GB"
        ));
    }
    fetch_buildroot(&d, &lock)?;

    let cargo = which_cargo()?;
    let commit = git_commit(root);
    const CHANNELS: &[&str] = &["stable", "testing", "long-term", "development"];
    if !CHANNELS.contains(&channel.as_str()) {
        return Err(format!("--channel {channel}: one of {CHANNELS:?}"));
    }
    // G1.6b: the image key (private: outside the tree and the image) and
    // what `corerouter-image seal` puts in the manifest.
    let image_tool = ab::tool(root)?;
    let (image_key, image_keys_dir) = ab::ensure_key(root, &image_tool, key.as_deref())?;
    let defconfig_text =
        std::fs::read_to_string(d.os.join("configs").join(DEFCONFIG)).map_err(|e| e.to_string())?;
    let seal_env = [
        ("CR_SEAL_TOOL", image_tool.display().to_string()),
        ("CR_SEAL_KEY", image_key.display().to_string()),
        (
            "CR_SEAL_IMAGE_KEYS_DIR",
            image_keys_dir.display().to_string(),
        ),
        ("CR_SEAL_VERSION", workspace_version(root)),
        ("CR_SEAL_BUILD", git_time(root).to_string()),
        ("CR_SEAL_CHANNEL", channel.clone()),
        ("CR_SEAL_KERNEL_VERSION", kernel_version(&defconfig_text)?),
        ("CR_SEAL_CONFIG_FORMAT", config_format(root)?.to_string()),
    ];
    let make = |targets: &[&str], parallel: Option<&String>| -> Result<(), String> {
        let mut cmd = Command::new("make");
        cmd.arg("-C")
            .arg(&d.buildroot)
            .arg(format!("O={}", d.out.display()));
        cmd.arg(format!("BR2_EXTERNAL={}", d.os.display()));
        cmd.arg(format!("COREROUTER_CARGO={}", cargo.display()));
        if let Some(j) = &jobs {
            cmd.arg(format!("BR2_JLEVEL={j}"));
        }
        if let Some(j) = parallel {
            cmd.arg(format!("-j{j}"));
        }
        cmd.args(targets);
        // The xtask's own cargo environment must not leak into Buildroot's
        // cargo call (target dir, manifest, the toolchain of this process).
        for var in [
            "CARGO_TARGET_DIR",
            "CARGO_MANIFEST_DIR",
            "CARGO_PKG_NAME",
            "RUSTFLAGS",
            "CARGO_BUILD_TARGET",
        ] {
            cmd.env_remove(var);
        }
        cmd.env("COREROUTER_COMMIT", &commit);
        for (k, v) in &seal_env {
            cmd.env(k, v);
        }
        let t = Instant::now();
        let st = cmd.status().map_err(|e| format!("make: {e}"))?;
        eprintln!(
            "   make {} — {:.1} s",
            targets.join(" "),
            t.elapsed().as_secs_f64()
        );
        if st.success() {
            Ok(())
        } else {
            Err(format!("make {} failed: {st}", targets.join(" ")))
        }
    };
    make(&[DEFCONFIG], None)?;
    // A custom kernel version is in BR_NO_CHECK_HASH_FOR (linux.mk):
    // Buildroot checks it only while linux.hash is there. Checked here too,
    // so deleting that file can never let an unchecked kernel in.
    make(&["linux-source"], None)?;
    let defconfig =
        std::fs::read_to_string(d.os.join("configs").join(DEFCONFIG)).map_err(|e| e.to_string())?;
    let version = kernel_version(&defconfig)?;
    let tarball =
        d.os.join("dl/linux")
            .join(format!("linux-{version}.tar.xz"));
    let hashes = std::fs::read_to_string(d.os.join("patches/linux/linux.hash"))
        .map_err(|e| e.to_string())?;
    let want = kernel_hash(&hashes, &version).ok_or("linux.hash: no hash for the kernel")?;
    let got = sha256_file(&tarball)?;
    if got != want {
        let _ = std::fs::remove_file(&tarball);
        return Err(format!(
            "{}: sha256 {got}, expected {want} (deleted)",
            tarball.display()
        ));
    }
    eprintln!("   linux-{version}.tar.xz: sha256 ok");
    // The workspace changes between builds; Buildroot only rebuilds a
    // package whose stamp is gone. cargo is incremental underneath.
    make(&["corerouter-dirclean"], None)?;
    // G1.6c: the installer kernel embeds the init: rebuilt after it
    // (kbuild relinks the initramfs and vmlinux only).
    let installer_dir = d.out.join("build").join(format!(
        "corerouter-installer-{}",
        kernel_version(&defconfig_text)?
    ));
    for stamp in [".stamp_built", ".stamp_images_installed"] {
        let _ = std::fs::remove_file(installer_dir.join(stamp));
    }
    // Buildroot reads the kernel fragment only when it configures the
    // kernel: a changed fragment needs `linux-reconfigure` (the kernel's
    // own make is incremental underneath).
    let fragment_hash = sha256_file(&d.os.join("board/x86_64/linux.fragment"))?;
    let stamp = d.out.join(".corerouter-linux-fragment.sha256");
    if std::fs::read_to_string(&stamp).ok().as_deref() != Some(fragment_hash.as_str()) {
        if d.out
            .join("build")
            .join(format!("linux-{version}/.config"))
            .exists()
        {
            make(&["linux-reconfigure"], None)?;
        }
        std::fs::write(&stamp, &fragment_hash).map_err(|e| format!("{}: {e}", stamp.display()))?;
    }
    make(&["all"], top_jobs.as_ref())?;

    let kconfig = std::fs::read_dir(d.out.join("build"))
        .map_err(|e| e.to_string())?
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n == format!("linux-{version}"))
        })
        .map(|p| p.join(".config"))
        .ok_or("no linux build directory")?;
    let kc =
        std::fs::read_to_string(&kconfig).map_err(|e| format!("{}: {e}", kconfig.display()))?;
    let fragment = std::fs::read_to_string(d.os.join("board/x86_64/linux.fragment"))
        .map_err(|e| e.to_string())?;
    let lost: Vec<&str> = fragment_symbols(&fragment)
        .into_iter()
        .filter(|s| !kc.lines().any(|l| l == format!("{s}=y")))
        .collect();
    if !lost.is_empty() {
        return Err(format!(
            "the kernel config dropped (missing dependency?): {}",
            lost.join(" ")
        ));
    }
    let ic = std::fs::read_to_string(installer_dir.join(".config"))
        .map_err(|e| format!("installer kernel .config: {e}"))?;
    // (BTF disappears from .config altogether once debug info is off.)
    for want in INSTALLER_KERNEL.iter().filter(|w| !w.contains("BTF")) {
        if !ic.lines().any(|l| l == *want) {
            return Err(format!("the installer kernel config lost '{want}'"));
        }
    }
    if ic.lines().any(|l| l == "CONFIG_DEBUG_INFO_BTF=y") {
        return Err("the installer kernel still has BTF".into());
    }
    let libs = check_needed(&d.out.join("target"))?;
    let images = d.out.join("images");
    let boot = std::fs::metadata(images.join("installer/EFI/BOOT/BOOTX64.EFI"))
        .map(|m| m.len())
        .unwrap_or(0);
    if boot + (1 << 20) > MAX_BOOT_IMAGE {
        return Err(format!(
            "the installer kernel ({boot} bytes) does not fit the boot image"
        ));
    }
    vm_images(root, &images)?;
    eprintln!(
        "\nimage ({} kernel options checked, {libs} ELF files find their libraries):",
        fragment_symbols(&fragment).len()
    );
    for f in [
        "disk.img",
        "bzImage",
        "rootfs.squashfs",
        "rootfs.img",
        "corerouter.crpkg",
        "installer/EFI/BOOT/BOOTX64.EFI",
        "corerouter-install.iso",
        "corerouter.qcow2",
        "corerouter.ova",
    ] {
        let p = images.join(f);
        let len = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
        let hash = sha256_file(&p).unwrap_or_default();
        eprintln!(
            "  {f:<30} {:>8.1} MiB  sha256 {hash}",
            len as f64 / 1048576.0
        );
    }
    eprintln!(
        "  built in {:.1} s → {}",
        started.elapsed().as_secs_f64(),
        images.display()
    );
    Ok(())
}

/// Every ELF file of the image finds each library it names (`DT_NEEDED`)
/// in `/lib` or `/usr/lib`: post-build.sh removes what FRR's build pulled
/// in and the image does not need (readline, ncurses, the C++ runtime);
/// this catches one removal too many. Returns how many files were checked.
fn check_needed(target: &Path) -> Result<usize, String> {
    let mut files = Vec::new();
    let mut stack = vec![target.to_owned()];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?
            .flatten()
        {
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                stack.push(e.path());
            } else if ft.is_file() {
                let mut magic = [0u8; 4];
                let is_elf = std::fs::File::open(e.path())
                    .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut magic))
                    .is_ok()
                    && magic == *b"\x7fELF";
                if is_elf {
                    files.push(e.path());
                }
            }
        }
    }
    let present = |name: &str| {
        ["lib", "usr/lib"].iter().any(|d| {
            let p = target.join(d).join(name);
            // A symlink must resolve inside the image.
            std::fs::canonicalize(&p).is_ok_and(|r| r.starts_with(target))
        })
    };
    let mut missing = Vec::new();
    for f in &files {
        let out = Command::new("readelf")
            .arg("-d")
            .arg(f)
            .output()
            .map_err(|e| format!("readelf: {e} (binutils)"))?;
        for l in String::from_utf8_lossy(&out.stdout).lines() {
            let Some(name) = l
                .contains("(NEEDED)")
                .then(|| l.rsplit('[').next()?.strip_suffix(']'))
                .flatten()
            else {
                continue;
            };
            if !present(name) {
                missing.push(format!(
                    "{} needs {name}",
                    f.strip_prefix(target).unwrap_or(f).display()
                ));
            }
        }
    }
    if missing.is_empty() {
        Ok(files.len())
    } else {
        Err(format!(
            "libraries missing from the image: {}",
            missing.join("; ")
        ))
    }
}

/// G1.6c: the VM images of `disk.img` (already the A/B layout; the first
/// boot creates the boot entries): qcow2 for KVM/Proxmox (compressed
/// clusters: a distribution image), and an OVA (streamOptimized VMDK +
/// OVF) for VMware/VirtualBox. With the host's `qemu-img`; without it the
/// build says so and goes on.
fn vm_images(root: &Path, images: &Path) -> Result<(), String> {
    let disk = images.join("disk.img");
    let have = Command::new("qemu-img")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !have {
        eprintln!("   no qemu-img on this host: corerouter.qcow2 and corerouter.ova not made");
        return Ok(());
    }
    let t = Instant::now();
    let conv = |args: &[&str], out: &Path| -> Result<(), String> {
        let st = Command::new("qemu-img")
            .args(["convert", "-q", "-f", "raw"])
            .args(args)
            .arg(&disk)
            .arg(out)
            .status()
            .map_err(|e| format!("qemu-img: {e}"))?;
        if st.success() {
            Ok(())
        } else {
            Err(format!("qemu-img convert → {}: {st}", out.display()))
        }
    };
    conv(
        &["-O", "qcow2", "-c", "-o", "compression_type=zlib"],
        &images.join("corerouter.qcow2"),
    )?;
    let tq = t.elapsed();
    let vmdk = images.join("corerouter-disk1.vmdk");
    conv(&["-O", "vmdk", "-o", "subformat=streamOptimized"], &vmdk)?;
    let capacity = std::fs::metadata(&disk)
        .map(|m| m.len())
        .map_err(|e| e.to_string())?;
    let tool = ab::tool(root)?;
    ab::run_tool(
        &tool,
        &[
            "ova",
            "--vmdk",
            &vmdk.display().to_string(),
            "--capacity",
            &capacity.to_string(),
            "--out",
            &images.join("corerouter.ova").display().to_string(),
        ],
    )?;
    let _ = std::fs::remove_file(&vmdk);
    eprintln!(
        "   VM images: qcow2 in {:.1} s, OVA in {:.1} s",
        tq.as_secs_f64(),
        (t.elapsed() - tq).as_secs_f64()
    );
    Ok(())
}

fn fetch_buildroot(d: &Dirs, lock: &Lock) -> Result<(), String> {
    let (patches, patches_hash) = buildroot_patches(&d.os)?;
    let stamp = d.buildroot.join(".corerouter-patches.sha256");
    if d.buildroot.join("Makefile").exists() {
        if std::fs::read_to_string(&stamp).ok().as_deref() == Some(patches_hash.as_str()) {
            return Ok(());
        }
        // A tree patched with other files (or before G1.6k): start over from
        // the tarball rather than patch on top of an old patch.
        eprintln!("   os/buildroot-patches changed: extracting Buildroot again");
        std::fs::remove_dir_all(&d.buildroot)
            .map_err(|e| format!("{}: {e}", d.buildroot.display()))?;
    }
    let name = lock.url.rsplit('/').next().unwrap_or("buildroot.tar.xz");
    let tarball = d.os.join("dl").join(name);
    if !tarball.exists() {
        eprintln!("   downloading {}", lock.url);
        download(&lock.url, &tarball)?;
    }
    let got = sha256_file(&tarball)?;
    if got != lock.sha256 {
        let _ = std::fs::remove_file(&tarball);
        return Err(format!(
            "{name}: sha256 {got}, expected {} (deleted)",
            lock.sha256
        ));
    }
    let st = Command::new("tar")
        .arg("-C")
        .arg(d.os.join("out"))
        .arg("-xf")
        .arg(&tarball)
        .status()
        .map_err(|e| format!("tar: {e}"))?;
    if !st.success() {
        return Err(format!("tar -xf {name}: {st}"));
    }
    for p in &patches {
        let st = Command::new("patch")
            .args(["-p1", "--batch", "--forward", "--silent", "-d"])
            .arg(&d.buildroot)
            .arg("-i")
            .arg(p)
            .status()
            .map_err(|e| format!("patch: {e}"))?;
        if !st.success() {
            return Err(format!("patch {}: {st}", p.display()));
        }
        eprintln!(
            "   applied {}",
            p.file_name().and_then(|n| n.to_str()).unwrap_or_default()
        );
    }
    std::fs::write(&stamp, &patches_hash).map_err(|e| format!("{}: {e}", stamp.display()))?;
    Ok(())
}

fn free_gb(dir: &Path) -> Result<u64, String> {
    let out = Command::new("df")
        .arg("-Pk")
        .arg(dir)
        .output()
        .map_err(|e| format!("df: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .nth(1)
        .and_then(|l| l.split_whitespace().nth(3))
        .and_then(|kb| kb.parse::<u64>().ok())
        .map(|kb| kb / (1024 * 1024))
        .ok_or_else(|| format!("df: unexpected output '{}'", text.trim()))
}

/// The cargo of the toolchain this workspace pins (rustup resolves
/// `rust-toolchain.toml` from the workspace directory).
fn which_cargo() -> Result<PathBuf, String> {
    let out = Command::new("rustup")
        .args(["which", "cargo"])
        .output()
        .map_err(|e| format!("rustup: {e}"))?;
    let p = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    if out.status.success() && !p.is_empty() {
        Ok(PathBuf::from(p))
    } else {
        Ok(PathBuf::from(crate::cargo_bin()))
    }
}

fn git_commit(root: &Path) -> String {
    Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .current_dir(root)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|| "dev".into())
}

// ------------------------------------------------------------- boot-test --

struct BootArgs {
    efi: bool,
    tcg: bool,
    timeout: Duration,
    append: String,
    keep_config: bool,
}

fn parse_boot_args(args: &[String]) -> Result<BootArgs, String> {
    let mut b = BootArgs {
        efi: false,
        tcg: false,
        timeout: Duration::from_secs(120),
        append: String::new(),
        keep_config: false,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--efi" => b.efi = true,
            "--tcg" => b.tcg = true,
            "--keep-config" => b.keep_config = true,
            "--timeout" => {
                let v = it.next().ok_or("--timeout needs seconds")?;
                b.timeout = Duration::from_secs(
                    v.parse()
                        .map_err(|_| format!("--timeout {v}: not a number"))?,
                );
            }
            "--append" => b.append = it.next().ok_or("--append needs kernel arguments")?.clone(),
            other => return Err(format!("unknown argument '{other}'\n{USAGE}")),
        }
    }
    Ok(b)
}

/// What the serial console said, as the test reads it.
#[derive(Default, Debug, PartialEq)]
struct Report {
    /// Seconds from kernel start to the first `pong` (from init's line).
    ready_kernel_s: Option<f64>,
    idle_kib: Option<u64>,
}

fn parse_ready(line: &str) -> Option<f64> {
    let rest = line.split("corerouter-init: ready:").nth(1)?;
    let at = rest.split(", ").nth(1)?;
    at.split_whitespace().next()?.parse().ok()
}

fn parse_idle(line: &str) -> Option<u64> {
    let rest = line.split("corerouter-init: idle: memory in use ").nth(1)?;
    rest.split_whitespace().next()?.parse().ok()
}

fn boot_test(root: &Path, args: &[String]) -> Result<(), String> {
    let b = parse_boot_args(args)?;
    let lock = parse_lock(
        &std::fs::read_to_string(root.join("os/buildroot.lock")).map_err(|e| e.to_string())?,
    )?;
    let images = dirs(root, &lock).out.join("images");
    let disk = images.join("disk.img");
    if !disk.exists() {
        return Err(format!(
            "{} missing: run `cargo xtask os build` first",
            disk.display()
        ));
    }
    let kvm = !b.tcg && kvm_usable();
    let port = free_port()?;
    let log_path = root.join("os/out/boot-test.log");
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args([
        "-machine",
        if kvm {
            "q35,accel=kvm"
        } else {
            "q35,accel=tcg"
        },
    ]);
    cmd.args([
        "-cpu",
        if kvm { "host" } else { "max" },
        "-smp",
        "2",
        "-m",
        "1024",
    ]);
    cmd.args([
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "stdio",
        "-no-reboot",
    ]);
    let snapshot = if b.keep_config { "" } else { ",snapshot=on" };
    cmd.arg("-drive").arg(format!(
        "file={},if=virtio,format=raw{snapshot}",
        disk.display()
    ));
    cmd.args(["-device", "virtio-rng-pci"]);
    cmd.arg("-netdev").arg(format!(
        "user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:{GUEST_TLS_PORT}"
    ));
    cmd.args(["-device", "virtio-net-pci,netdev=n0"]);
    let vars = root.join("os/out/OVMF_VARS.fd");
    if b.efi {
        let code = "/usr/share/OVMF/OVMF_CODE_4M.fd";
        std::fs::copy("/usr/share/OVMF/OVMF_VARS_4M.fd", &vars)
            .map_err(|e| format!("OVMF vars: {e} (package ovmf)"))?;
        cmd.arg("-drive")
            .arg(format!("if=pflash,format=raw,readonly=on,file={code}"));
        cmd.arg("-drive")
            .arg(format!("if=pflash,format=raw,file={}", vars.display()));
        if !b.append.is_empty() {
            eprintln!(
                "note: --append is ignored with --efi (the command line is built into the kernel)"
            );
        }
    } else {
        cmd.arg("-kernel").arg(images.join("bzImage"));
        // The image has no address on any port until it is configured (a
        // first-boot default, DHCP client on ether1 like a CHR, is G1.6d):
        // the test gives eth0 QEMU's user-network address with the kernel's
        // own `ip=`, appended to the built-in command line.
        cmd.arg("-append")
            .arg(format!("{GUEST_IP_ARG} {}", b.append).trim_end());
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    eprintln!(
        "booting {} ({}, {}), TLS control on 127.0.0.1:{port}, console → {}",
        disk.display(),
        if kvm { "KVM" } else { "TCG" },
        if b.efi {
            "UEFI → EFI stub"
        } else {
            "-kernel"
        },
        log_path.display()
    );
    let started = Instant::now();
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("qemu-system-x86_64: {e}"))?;
    let res = watch(&mut child, &b, port, started, &log_path);
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&vars);
    let (report, wall_ready, ping) = res?;
    eprintln!("\nboot-test ok ({}):", if kvm { "KVM" } else { "TCG" });
    eprintln!(
        "  kernel start → daemon answers ping: {:.3} s (corerouter-init)",
        report.ready_kernel_s.unwrap_or(-1.0)
    );
    eprintln!(
        "  qemu start → ready line:            {:.3} s (wall, includes firmware)",
        wall_ready.as_secs_f64()
    );
    eprintln!("  TLS ping from the host:             {ping}");
    if let Some(kib) = report.idle_kib {
        eprintln!(
            "  idle memory in use:                 {:.1} MiB",
            kib as f64 / 1024.0
        );
    }
    Ok(())
}

fn watch(
    child: &mut Child,
    b: &BootArgs,
    port: u16,
    started: Instant,
    log_path: &Path,
) -> Result<(Report, Duration, String), String> {
    let stdout = child.stdout.take().ok_or("qemu: no stdout")?;
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::Builder::new()
        .name("qemu-serial".into())
        .spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        })
        .map_err(|e| e.to_string())?;
    let mut log =
        std::fs::File::create(log_path).map_err(|e| format!("{}: {e}", log_path.display()))?;
    let mut report = Report::default();
    let mut wall_ready = None;
    let mut ping = None;
    let deadline = started + b.timeout;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(format!(
                "timeout after {} s (console in {})",
                b.timeout.as_secs(),
                log_path.display()
            ));
        }
        let line = match rx.recv_timeout(left.min(Duration::from_millis(500))) {
            Ok(l) => l,
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(format!(
                    "qemu exited (kernel panic or poweroff?): console in {}",
                    log_path.display()
                ));
            }
        };
        let _ = writeln!(log, "{line}");
        if line.contains("corerouter-init") || line.contains("Kernel panic") {
            eprintln!("  | {line}");
        }
        if line.contains("Kernel panic") {
            return Err(format!("kernel panic (console in {})", log_path.display()));
        }
        if let Some(s) = parse_ready(&line).filter(|_| report.ready_kernel_s.is_none()) {
            report.ready_kernel_s = Some(s);
            wall_ready = Some(started.elapsed());
            ping = Some(if b.efi {
                "skipped: with --efi the command line is the built-in one, no address on eth0 (G1.6d)".to_owned()
            } else {
                tls_ping(port)?
            });
        }
        if let Some(k) = parse_idle(&line) {
            report.idle_kib = Some(k);
        }
        if let (Some(w), Some(p), Some(_)) = (wall_ready, &ping, report.idle_kib) {
            return Ok((report, w, p.clone()));
        }
    }
}

/// `{"method":"ping"}` over TLS through QEMU's port forward (the daemon's
/// self-signed certificate is not checked: this proves it answers, not who
/// it is). `openssl s_client` keeps xtask free of a TLS stack.
fn tls_ping(port: u16) -> Result<String, String> {
    let t = Instant::now();
    let mut child = Command::new("openssl")
        .args(["s_client", "-quiet", "-ign_eof", "-connect"])
        .arg(format!("127.0.0.1:{port}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("openssl: {e}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"{\"id\":1,\"method\":\"ping\"}\n");
        // Kept open: closing it would end the session before the answer.
        std::mem::forget(stdin);
    }
    let stdout = child.stdout.take().ok_or("openssl: no stdout")?;
    let (tx, rx) = mpsc::channel();
    let _ = std::thread::Builder::new()
        .name("tls-ping".into())
        .spawn(move || {
            let mut line = String::new();
            let _ = BufReader::new(stdout).read_line(&mut line);
            let _ = tx.send(line);
        });
    let got = rx.recv_timeout(Duration::from_secs(10));
    let _ = child.kill();
    let _ = child.wait();
    match got {
        Ok(l) if l.contains("\"pong\":true") => {
            Ok(format!("{} in {} ms", l.trim(), t.elapsed().as_millis()))
        }
        Ok(l) => Err(format!("TLS ping: unexpected answer '{}'", l.trim())),
        Err(_) => Err("TLS ping: no answer in 10 s".into()),
    }
}

fn kvm_usable() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

fn free_port() -> Result<u16, String> {
    let l = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    l.local_addr().map(|a| a.port()).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real `os/` tree passes the static checks: this is how
    /// `cargo xtask ci` validates the image configuration without
    /// downloading or building anything.
    #[test]
    fn os_tree_is_consistent() {
        let os = Path::new(env!("CARGO_MANIFEST_DIR")).join("../os");
        let n = check(&os).unwrap();
        assert!(n > 40, "{n}");
    }

    #[test]
    fn lock_and_hash_parsing() {
        let l = parse_lock(
            &("# x\nversion = 1.2\nurl = https://e/b-1.2.tar.xz\nsha256 = ".to_owned()
                + &"a".repeat(64)),
        )
        .unwrap();
        assert_eq!(l.version, "1.2");
        assert!(parse_lock("version = 1\nurl = http://e/1\nsha256 = 00").is_err());
        let h = format!(
            "# c\nsha256  {}  linux-6.18.59.tar.xz\nsha256  {}  COPYING\n",
            "b".repeat(64),
            "c".repeat(64)
        );
        assert_eq!(kernel_hash(&h, "6.18.59"), Some("b".repeat(64)));
        assert_eq!(kernel_hash(&h, "6.18.60"), None);
    }

    #[test]
    fn fragment_and_genimage_parsing() {
        let f = "# c\nCONFIG_A=y\nCONFIG_B=m\n# CONFIG_C is not set\nCONFIG_CMDLINE=\"root=PARTUUID=u1 ro\"\n";
        assert_eq!(fragment_symbols(f), ["CONFIG_A"]);
        assert_eq!(
            config_value(f, "CONFIG_CMDLINE"),
            Some("root=PARTUUID=u1 ro")
        );
        let g = "partition efi {\n partition-uuid = \"e\"\n}\npartition rootfs-a {\n image = \"r\"\n partition-uuid = \"u1\"\n}\n";
        assert_eq!(genimage_partuuid(g, "rootfs-a").as_deref(), Some("u1"));
        assert_eq!(genimage_partuuid(g, "rootfs-b"), None);
    }

    #[test]
    fn console_lines() {
        let l = "corerouter-init: ready: control channel answered ping, 1.234 s after kernel start (init +0.400 s, daemon start +0.300 s)";
        assert_eq!(parse_ready(l), Some(1.234));
        assert_eq!(parse_ready("[    1.0] random"), None);
        assert_eq!(
            parse_idle("corerouter-init: idle: memory in use 51234 KiB (MemTotal − MemAvailable)"),
            Some(51234)
        );
    }

    #[test]
    fn boot_args() {
        let a: Vec<String> = [
            "--efi",
            "--timeout",
            "30",
            "--append",
            "corerouter.shell=ttyS0",
        ]
        .map(String::from)
        .into();
        let b = parse_boot_args(&a).unwrap();
        assert!(
            b.efi && !b.tcg && b.timeout.as_secs() == 30 && b.append == "corerouter.shell=ttyS0"
        );
        assert!(parse_boot_args(&["--bogus".into()]).is_err());
    }
}

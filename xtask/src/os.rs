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
//! - G1.6o: `build` first builds the browser GUI with trunk (release,
//!   wasm-opt; pinned tools, `os/web.rs`) into `<out>/web`, which
//!   `corerouter.mk` installs as `/usr/share/corerouter/web`.
//! - G1.6k: `build` applies `os/buildroot-patches/*.patch` to the extracted
//!   Buildroot tree (package versions newer than the LTS branch ships, FRR
//!   10.7.1) and extracts it again when those patches change; `frr-test`
//!   runs OSPF/SR/LDP/BFD between two guests of the image (`os/frr.rs`).
//! - G1.26i: `forward-test` routes IPv4 and IPv6 between two guests through
//!   a third nobody tuned, and reads the live ISO's forwarding
//!   (`os/forward.rs`).
//! - processo: everything built lives in one directory per checkout, by
//!   default on the build disk outside the repository (`os/out.rs`), and
//!   `make all` runs packages in parallel by default.

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::Outcome;
use crate::vm_lab::{download, sha256_file};

mod ab;
mod firmware;
mod forward;
mod frr;
mod hotplug;
mod install;
mod livemods;
mod out;
mod push;
mod release;
mod web;
mod wifi;

/// G1.6j: the families an operator buys, to catch a list regenerated wrong.
const REQUIRED_NICS: &[&str] = &[
    "CONFIG_BNXT",
    "CONFIG_BNX2X",
    "CONFIG_MLX4_EN",
    "CONFIG_CHELSIO_T4",
    "CONFIG_QEDE",
    "CONFIG_SFC",
    "CONFIG_AQTION",
    "CONFIG_DWMAC_INTEL",
    "CONFIG_USB_RTL8150",
    // G1.30: Wi-Fi in station mode. The stack as a module (built in, it asks
    // for the regulatory database before / is mounted and never gets it),
    // one driver of each family, and the simulated radios `boot-test --wifi`
    // loads.
    "CONFIG_CFG80211",
    "CONFIG_MAC80211",
    "CONFIG_IWLMVM",
    "CONFIG_IWLMLD",
    "CONFIG_MT7921E",
    "CONFIG_MT7925E",
    "CONFIG_RTW88_8822CE",
    "CONFIG_RTW89_8852BE",
    "CONFIG_MAC80211_HWSIM",
];

const DEFCONFIG: &str = "corerouter_x86_64_defconfig";
/// Free space the build wants before it starts (cold build: ~8 GB in
/// the out directory, **medido**; the rest is headroom for parallel sessions).
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
    "CONFIG_MODULES",
    "CONFIG_FW_LOADER",
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
    // G1.6zc: the screen console after a UEFI boot (no VGA text mode there).
    "CONFIG_SYSFB_SIMPLEFB",
    "CONFIG_DRM_SIMPLEDRM",
    "CONFIG_DRM_FBDEV_EMULATION",
    "CONFIG_FRAMEBUFFER_CONSOLE",
];
/// G1.6j: drivers that must be modules. `ice` asks for its firmware while
/// probing, which a built-in driver does before `/` is mounted; `e100` and
/// `pcnet32` are what `boot-test` sees (QEMU emulates them).
/// G1.6zd: `i915` is one too (GuC, HuC and DMC at probe); built in, an Intel
/// GPU of the 12th generation or later fails to start and the console shows
/// four error lines at every boot.
const REQUIRED_MODULES: &[&str] = &[
    "CONFIG_ICE",
    "CONFIG_E100",
    "CONFIG_PCNET32",
    "CONFIG_DRM_I915",
];
/// G1.6zf: the sensors System › Health reads, built in: these drivers bind
/// only to a device the machine enumerates (CPUID, PCI, an NVMe controller,
/// a SATA disk). A notebook showed one ACPI zone and no CPU or NVMe
/// temperature: none of them was on.
const SENSORS_BUILT_IN: &[&str] = &[
    "CONFIG_SENSORS_CORETEMP",
    "CONFIG_SENSORS_K10TEMP",
    "CONFIG_NVME_HWMON",
    "CONFIG_SENSORS_DRIVETEMP",
];
/// G1.6zf: the motherboard's Super-I/O drivers, (kernel symbol, module).
/// Modules, never built in: each writes to I/O ports 0x2e/0x4e to find its
/// chip, so PID 1 decides when (never in a VM, `corerouter.sensors=off`).
/// The names are `SENSOR_MODULES` of `corerouter-init`.
const SENSOR_MODULES: &[(&str, &str)] = &[
    ("CONFIG_SENSORS_NCT6775", "nct6775"),
    ("CONFIG_SENSORS_NCT6683", "nct6683"),
    ("CONFIG_SENSORS_IT87", "it87"),
    ("CONFIG_SENSORS_F71882FG", "f71882fg"),
    ("CONFIG_SENSORS_W83627EHF", "w83627ehf"),
];
/// What the kernel must not have (`# … is not set` in the fragment, absent
/// from the built `.config`). G1.6zd: a router plays no sound, and on a
/// notebook `snd_hda_intel` wrote "Cannot probe codecs, giving up" on the
/// console at every boot (the x86_64 defconfig turns it on).
/// G1.6zi: nor a classic Xen PV guest (`PARAVIRT_XXL` spreads indirect
/// calls over the kernel), a balloon that hands the router's memory back to
/// the host, or DMA remapping on by default on Intel (interrupt remapping is
/// on; translating every DMA is a throughput decision to measure first).
const KERNEL_OFF: &[&str] = &[
    "CONFIG_SOUND",
    "CONFIG_XEN_PV",
    "CONFIG_XEN_BALLOON",
    "CONFIG_INTEL_IOMMU_DEFAULT_ON",
];
/// G1.6zi: what lets the image boot, see its disk and use every core on
/// common hardware, and say what went wrong: `check` wants each `=y` in the
/// fragment, and `build` fails when the configured kernel dropped one.
const HARDWARE_COVERAGE: &[&str] = &[
    // Every core: 8192 CPUs (the defconfig's 64 left the rest of a server
    // unused), and more than 255 APIC ids: x2APIC needs interrupt remapping.
    "CONFIG_MAXSMP",
    "CONFIG_IRQ_REMAP",
    // The disk the router boots from: eMMC/SD, NVMe behind Intel VMD, HPE
    // Smart Array Gen10+, Broadcom MPI3.
    "CONFIG_MMC",
    "CONFIG_MMC_BLOCK",
    "CONFIG_MMC_SDHCI",
    "CONFIG_MMC_SDHCI_PCI",
    "CONFIG_MMC_SDHCI_ACPI",
    "CONFIG_VMD",
    "CONFIG_SCSI_SMARTPQI",
    "CONFIG_SCSI_MPI3MR",
    "CONFIG_USB_UAS",
    // Hyper-V/Azure and Xen HVM: disk and port.
    "CONFIG_HYPERV",
    "CONFIG_HYPERV_VMBUS",
    "CONFIG_HYPERV_STORAGE",
    "CONFIG_HYPERV_NET",
    "CONFIG_HYPERV_KEYBOARD",
    "CONFIG_HYPERV_UTILS",
    "CONFIG_XEN",
    "CONFIG_XEN_PVHVM_GUEST",
    "CONFIG_XEN_BLKDEV_FRONTEND",
    "CONFIG_XEN_NETDEV_FRONTEND",
    "CONFIG_PARAVIRT_SPINLOCKS",
    "CONFIG_VIRT_DRIVERS",
    "CONFIG_VMGENID",
    // A hang, a panic, a PCIe or memory error leaves a trace.
    "CONFIG_SOFTLOCKUP_DETECTOR",
    "CONFIG_HARDLOCKUP_DETECTOR",
    // Each CPU watches its neighbour: no PMU counter, works in a VM.
    "CONFIG_HARDLOCKUP_DETECTOR_PREFER_BUDDY",
    "CONFIG_DETECT_HUNG_TASK",
    "CONFIG_PSTORE",
    "CONFIG_PSTORE_COMPRESS",
    "CONFIG_EFI_VARS_PSTORE",
    // With pstore on, or panics would fill the NVRAM of the A/B boot entries.
    "CONFIG_EFI_VARS_PSTORE_DEFAULT_DISABLE",
    "CONFIG_PCIEAER",
    "CONFIG_PCIE_DPC",
    "CONFIG_RAS",
    "CONFIG_ACPI_APEI",
    "CONFIG_ACPI_APEI_GHES",
    "CONFIG_ACPI_APEI_PCIEAER",
    "CONFIG_ACPI_EXTLOG",
    "CONFIG_EDAC",
    "CONFIG_EDAC_DECODE_MCE",
    "CONFIG_EDAC_AMD64",
    "CONFIG_EDAC_SKX",
    "CONFIG_EDAC_I10NM",
    "CONFIG_EDAC_SBRIDGE",
    "CONFIG_EDAC_IE31200",
];
/// G1.6zi: what both built `.config`s must say, as a value: `MAXSMP` took
/// effect (it is dropped in silence without `DEBUG_KERNEL`).
const KERNEL_VALUES: &[&str] = &["CONFIG_NR_CPUS=8192"];
/// What the ISO's kernel must not have, on top of [`KERNEL_OFF`]. G1.30: no
/// Wi-Fi stack in the live image (joining a network is the installed
/// router's), so no card driver is built for it and its module payload does
/// not grow by them.
const INSTALLER_OFF: &[&str] = &["CONFIG_CFG80211", "CONFIG_WLAN"];
/// Buildroot options the image's design rests on (docs/os-image.md).
const REQUIRED_BR2: &[&str] = &[
    "BR2_INIT_NONE=y",
    "BR2_TARGET_ROOTFS_SQUASHFS=y",
    // G1.6g: post-image.sh makes the BIOS images with its grub-mkimage.
    "BR2_TARGET_GRUB2=y",
    "BR2_TARGET_GRUB2_I386_PC=y",
    "BR2_REPRODUCIBLE=y",
    "BR2_DOWNLOAD_FORCE_CHECK_HASHES=y",
    "BR2_PER_PACKAGE_DIRECTORIES=y",
    "BR2_PACKAGE_COREROUTER=y",
    "BR2_PACKAGE_COREROUTER_FIRMWARE=y",
    "BR2_PACKAGE_NFTABLES=y",
    "# BR2_TARGET_ENABLE_ROOT_LOGIN is not set",
    "BR2_PACKAGE_FRR=y",
    "BR2_PACKAGE_LIBCAP=y",
    "BR2_PACKAGE_COREROUTER_INSTALLER=y",
    // G1.6v: corerouter-init grows /config with them.
    "BR2_PACKAGE_E2FSPROGS=y",
    "BR2_PACKAGE_E2FSPROGS_RESIZE2FS=y",
    // G1.30: Wi-Fi in station mode. WPA3 is what brings SAE (and OpenSSL).
    "BR2_PACKAGE_WPA_SUPPLICANT=y",
    "BR2_PACKAGE_WPA_SUPPLICANT_NL80211=y",
    "BR2_PACKAGE_WPA_SUPPLICANT_WPA3=y",
    "BR2_PACKAGE_WPA_SUPPLICANT_CTRL_IFACE=y",
    "BR2_PACKAGE_WIRELESS_REGDB=y",
];
/// What the installer kernel's fragment must say (G1.6c).
const INSTALLER_KERNEL: &[&str] = &[
    "CONFIG_CMDLINE=\"console=tty0 console=ttyS0,115200 corerouter.mode=live bonding.max_bonds=0 dummy.numdummies=0 panic=10 quiet\"",
    "CONFIG_INITRAMFS_COMPRESSION_ZSTD=y",
    "# CONFIG_DEBUG_INFO_BTF is not set",
    // G1.6j: built in, or the installer would not show an E810 port.
    "CONFIG_ICE=y",
    // G1.6za: another release, so a module of the image's kernel cannot load
    // in this one (and the reverse). `livemods::SUFFIX`.
    "CONFIG_LOCALVERSION=\"-live\"",
];
/// G1.6m, G1.6ze: on both kernels' command lines, or the built-in drivers
/// create `bond0` and `dummy0` by themselves and the router lists them.
const NO_KERNEL_DEVICES: [&str; 2] = ["bonding.max_bonds=0", "dummy.numdummies=0"];
/// G1.6ze: what makes the installer's kernel take `os/patches/linux` (the
/// tunnels' catch-all devices are turned off by one of them).
const INSTALLER_PATCH_HOOK: &str =
    "$(APPLY_PATCHES) $(@D) $(BR2_EXTERNAL_COREROUTER_PATH)/patches/linux \\*.patch";
/// The modules `boot-test` and `install-test` see, by file name.
const REQUIRED_MODULE_FILES: &[&str] = &["e100", "pcnet32"];
/// The installer's boot image (El Torito counts 16-bit 512-byte sectors).
const MAX_BOOT_IMAGE: u64 = 65535 * 512;
const INIT_PATH: &str = "/usr/sbin/corerouter-init";
/// eth0 on QEMU's user network (slirp: guest 10.0.2.15, gateway 10.0.2.2),
/// set by the kernel before init (`CONFIG_IP_PNP`).
const GUEST_IP_ARG: &str = "ip=10.0.2.15::10.0.2.2:255.255.255.0::eth0:off";
/// The daemon's TLS control port inside the image (corerouter-init's plan).
const GUEST_TLS_PORT: u16 = 8729;
/// G1.6o: `ip.service www-ssl`, on in a new config of the image.
const GUEST_WEB_PORT: u16 = 443;

const USAGE: &str = "usage: cargo xtask os <build [--only crpkg] [--jobs N] [--top-jobs N] [--key PKCS8] [--channel C]|push --to HOST:PORT [--user U] [--no-build] [--no-wait] [--confirm manual]|release-key <init|check> [--dir D]|release --tag vX.Y.Z [--key-dir D] [--dry-run] [--no-build] [--repo OWNER/NAME]|out-dir|boot-test [--efi] [--tcg] [--wifi] [--timeout S] [--append ARGS] [--keep-config] [--smp N]|ab-test [--tcg] [--firmware ovmf|seabios] [--scenario update|push|no-confirm|bad-signature|bad-param|cross|cut|controllers]|install-test [--tcg] [--firmware ovmf|seabios] [--only live-modules|sd]|frr-test [--tcg]|wifi-test [--tcg] [--only commands|setup]|forward-test [--tcg] [--no-live]|firmware-lock --tag T|package --out FILE [--version V] [--build N] [--channel C] [--key PKCS8]|check>";

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
        "wifi-test" => images_dir(root).and_then(|i| wifi::wifi_test(root, &i, rest)),
        "forward-test" => images_dir(root).and_then(|i| forward::forward_test(root, &i, rest)),
        "package" => images_dir(root).and_then(|i| package_cmd(root, &i, rest)),
        "firmware-lock" => images_dir(root).and_then(|i| {
            let target = i
                .parent()
                .map(|p| p.join("target"))
                .ok_or("no target directory")?;
            firmware::lock_cmd(root, &target, rest)
        }),
        "push" => images_dir(root).and_then(|i| push::push(root, &i, rest)),
        "release-key" => release::release_key(root, rest),
        "release" => release::release(root, rest),
        "out-dir" => out::resolve(root).map(|o| println!("{}", o.dir.display())),
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
        cmd.arg("--keys").arg(out_dir(root)?.join("keys"));
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
    Ok(dirs(root, &out_dir(root)?, &lock).out.join("images"))
}

/// Where this checkout's image build lives (`os/out.rs`).
fn out_dir(root: &Path) -> Result<PathBuf, String> {
    out::resolve(root).map(|o| o.dir)
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

/// G0.32: a development image's version, `0.1.0-dev.<N>` (N = commits on
/// HEAD), the same the daemon inside it reports (`corerouter-buildinfo`).
/// A release passes the tag's version instead.
fn dev_version(root: &Path) -> String {
    let n = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-list", "--count", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse::<u64>()
                .ok()
        })
        .unwrap_or(0);
    format!("{}-dev.{n}", workspace_version(root))
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

/// The `=m` symbols of a kernel config fragment.
fn module_symbols(fragment: &str) -> Vec<&str> {
    fragment
        .lines()
        .filter_map(|l| l.strip_suffix("=m"))
        .filter(|s| s.starts_with("CONFIG_"))
        .collect()
}

/// The first symbol of `off` a kernel `.config` has on (`=y` or `=m`).
fn kernel_on<'a>(config: &str, off: &[&'a str]) -> Option<&'a str> {
    off.iter().copied().find(|s| {
        config
            .lines()
            .any(|l| l.strip_prefix(s).is_some_and(|v| v == "=y" || v == "=m"))
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
    // processo: the release public keys the images trust.
    n += release::release_keys(&os.join("keys/release"))?.len();
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
    for want in REQUIRED_MODULES {
        if !fragment.lines().any(|l| l == format!("{want}=m")) {
            return Err(format!("linux.fragment: {want}=m is required"));
        }
        n += 1;
    }
    for off in KERNEL_OFF {
        if !fragment.lines().any(|l| l == format!("# {off} is not set")) {
            return Err(format!("linux.fragment: '# {off} is not set' is required"));
        }
        n += 1;
    }
    for want in HARDWARE_COVERAGE {
        if !syms.contains(want) {
            return Err(format!(
                "linux.fragment: {want}=y is required (hardware coverage, docs/os-image.md)"
            ));
        }
        n += 1;
    }
    let init = std::fs::read_to_string(os.join("../apps/corerouter-init/src/modules.rs"))
        .map_err(|e| format!("apps/corerouter-init/src/modules.rs: {e}"))?;
    n += check_sensors(&fragment, &init)?;
    let nics = read("board/x86_64/nics.fragment")?;
    let wide = module_symbols(&nics);
    for want in REQUIRED_NICS {
        if !wide.contains(want) {
            return Err(format!("nics.fragment: {want}=m is required"));
        }
        n += 1;
    }
    n += firmware::check(os)?;
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
    no_kernel_devices("linux.fragment", cmdline)?;
    n += 1;
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
    patches_in(&os.join("buildroot-patches"))
}

/// The `*.patch` files of `dir` in name order and one hash over their names
/// and contents.
fn patches_in(dir: &Path) -> Result<(Vec<PathBuf>, String), String> {
    let mut patches: Vec<PathBuf> = match std::fs::read_dir(dir) {
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

/// G1.6zf: the fragment has the built-in sensors and the Super-I/O drivers as
/// modules, and PID 1 (`init`: the text of its `modules.rs`) loads exactly
/// those modules.
fn check_sensors(fragment: &str, init: &str) -> Result<usize, String> {
    let built_in = fragment_symbols(fragment);
    if let Some(want) = SENSORS_BUILT_IN.iter().find(|s| !built_in.contains(s)) {
        return Err(format!(
            "linux.fragment: {want}=y is required (System › Health has no such sensor without it)"
        ));
    }
    let modules = module_symbols(fragment);
    for (symbol, _) in SENSOR_MODULES {
        if !modules.contains(symbol) {
            return Err(format!(
                "linux.fragment: {symbol}=m is required (a module: it pokes I/O ports to find its chip, PID 1 decides when)"
            ));
        }
    }
    let list = init
        .lines()
        .find_map(|l| l.strip_prefix("pub const SENSOR_MODULES: ["))
        .and_then(|l| l.split_once("] = [")?.1.strip_suffix("];"))
        .ok_or("corerouter-init modules.rs: no `pub const SENSOR_MODULES: [&str; N] = [...];` on one line")?;
    let mut loaded: Vec<&str> = list
        .split(',')
        .map(|m| m.trim().trim_matches('"'))
        .collect();
    let mut built: Vec<&str> = SENSOR_MODULES.iter().map(|(_, m)| *m).collect();
    loaded.sort_unstable();
    built.sort_unstable();
    if loaded != built {
        return Err(format!(
            "corerouter-init loads the sensor modules {loaded:?}, the kernel builds {built:?}"
        ));
    }
    Ok(SENSORS_BUILT_IN.len() + SENSOR_MODULES.len() + 1)
}

/// G1.6m, G1.6ze: the command line of `what` keeps the built-in drivers from
/// creating devices of their own.
fn no_kernel_devices(what: &str, cmdline: &str) -> Result<(), String> {
    match NO_KERNEL_DEVICES
        .iter()
        .find(|p| !cmdline.split_whitespace().any(|w| w == **p))
    {
        Some(p) => Err(format!(
            "{what}: CONFIG_CMDLINE needs '{p}' (the driver is built in and would create its own device)"
        )),
        None => Ok(()),
    }
}

/// The patches of `patches` that Buildroot did not apply to the kernel tree
/// `tree`, by file name (its `.applied_patches_list`, written by
/// `support/scripts/apply-patches.sh`). G1.6ze: the installer's kernel was
/// built from the plain tarball since the patches exist, and nothing said so.
fn patches_missing(tree: &Path, patches: &[PathBuf]) -> Vec<String> {
    let applied = std::fs::read_to_string(tree.join(".applied_patches_list")).unwrap_or_default();
    let applied: Vec<&str> = applied
        .lines()
        .filter_map(|l| l.rsplit('/').next())
        .collect();
    patches
        .iter()
        .filter_map(|p| p.file_name().and_then(|n| n.to_str()))
        .filter(|n| !applied.contains(n))
        .map(str::to_owned)
        .collect()
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
    for off in INSTALLER_OFF {
        if !frag.lines().any(|l| l == format!("# {off} is not set")) {
            return Err(format!(
                "installer.fragment: '# {off} is not set' is required"
            ));
        }
        n += 1;
    }
    if frag
        .lines()
        .any(|l| !l.starts_with('#') && l.contains("root="))
    {
        return Err("installer.fragment: the installer runs from its initramfs (no root=)".into());
    }
    no_kernel_devices(
        "installer.fragment",
        config_value(&frag, "CONFIG_CMDLINE").unwrap_or_default(),
    )?;
    n += 1;
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
    // G1.6ze: the same kernel source too, patches included.
    if !mk.contains(INSTALLER_PATCH_HOOK)
        || !mk.contains("COREROUTER_INSTALLER_POST_PATCH_HOOKS += ")
    {
        return Err(format!(
            "corerouter-installer.mk: the installer's kernel must apply os/patches/linux ('{INSTALLER_PATCH_HOOK}' in a POST_PATCH hook)"
        ));
    }
    n += 1;
    // G1.6za: the ISO's modules, with no link back to the build machine.
    for want in ["modules_install", "live-modules.img", "rm -f"] {
        if !mk.contains(want) {
            return Err(format!("corerouter-installer.mk: no '{want}' (G1.6za)"));
        }
    }
    if !frag.contains(&format!("CONFIG_LOCALVERSION=\"{}\"", livemods::SUFFIX)) {
        return Err("installer.fragment: the ISO's kernel needs its own release".into());
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
    /// Everything built (`os/out.rs`).
    top: PathBuf,
    buildroot: PathBuf,
    /// Buildroot's `O=`.
    out: PathBuf,
}

fn dirs(root: &Path, top: &Path, lock: &Lock) -> Dirs {
    Dirs {
        os: root.join("os"),
        top: top.to_owned(),
        buildroot: top.join(format!("buildroot-{}", lock.version)),
        out: top.join("build"),
    }
}

/// processo (release da imagem): a build of a tagged version, made by
/// `os release` (`os/release.rs`).
pub(crate) struct ReleaseBuild {
    /// The build directory (apart from the development one).
    pub top: PathBuf,
    /// The decrypted release key, for the time of the build.
    pub key: PathBuf,
    /// The manifest's version (the tag without the `v`).
    pub version: String,
    pub channel: String,
}

fn build(root: &Path, args: &[String]) -> Result<(), String> {
    build_with(root, args, None)
}

pub(crate) fn build_with(
    root: &Path,
    args: &[String],
    release: Option<&ReleaseBuild>,
) -> Result<(), String> {
    let mut jobs: Option<String> = None;
    let mut top_jobs: Option<String> = None;
    let mut key: Option<PathBuf> = None;
    let mut channel = "development".to_owned();
    let mut only_crpkg = false;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--only" => match it.next().map(String::as_str) {
                Some("crpkg") => only_crpkg = true,
                other => {
                    return Err(format!(
                        "--only {}: only 'crpkg' is known",
                        other.unwrap_or("?")
                    ));
                }
            },
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
    let o = match release {
        Some(r) => out::Out {
            dir: r.top.clone(),
            source: out::Source::Env,
        },
        None => out::resolve(root)?,
    };
    if let Some(r) = release {
        key = Some(r.key.clone());
        channel = r.channel.clone();
    }
    let d = dirs(root, &o.dir, &lock);
    std::fs::create_dir_all(d.os.join("dl")).map_err(|e| e.to_string())?;
    let _lock = out::lock(&d.top)?;
    eprintln!("   out: {}", d.top.display());
    if o.source == out::Source::Legacy {
        eprintln!(
            "   warning: the build is inside the checkout (os/out, it holds the signing key); \
             move it to the build disk: docs/os-image.md, \"Onde fica o build\""
        );
    }
    let free = free_gb(&d.top)?;
    if free < MIN_FREE_GB {
        return Err(format!(
            "only {free} GB free under {}; the build wants {MIN_FREE_GB} GB",
            d.top.display()
        ));
    }
    fetch_buildroot(&d, &lock)?;
    // G1.6j: the firmware files firmware.lock pins, hash checked.
    let firmware_stage = firmware::stage(&d.os, &d.top)?;
    // G1.6o: the browser GUI that `ip.service www-ssl` serves. processo:
    // in its own cargo target. Sharing `cargo-target` with the image's
    // cargo (whose build scripts the Buildroot gcc links) made each build
    // throw away the other's host artifacts: every `os build` recompiled
    // the GUI (216 s) and all of the daemon's dependencies (**medido**).
    let web_dir = web::build(root, &d.top, &d.top.join("web-target"))?;

    let cargo = which_cargo()?;
    let commit = git_commit(root);
    const CHANNELS: &[&str] = &["stable", "testing", "long-term", "development"];
    if !CHANNELS.contains(&channel.as_str()) {
        return Err(format!("--channel {channel}: one of {CHANNELS:?}"));
    }
    // G1.6b: the image key (private: outside the tree and the image) and
    // what `corerouter-image seal` puts in the manifest.
    let image_tool = ab::tool(root)?;
    let (image_key, signing_pub) = ab::ensure_key(&d.top, &image_tool, key.as_deref())?;
    // processo: the public keys the image trusts. A development image: its
    // own key and the release keys of `os/keys/release/` (a test router
    // takes both). A release image: only the release keys.
    let image_keys_dir = release::trust_dir(
        &d.top,
        &signing_pub,
        &d.os.join("keys/release"),
        release.is_some(),
    )?;
    let defconfig_text =
        std::fs::read_to_string(d.os.join("configs").join(DEFCONFIG)).map_err(|e| e.to_string())?;
    let seal_env = [
        ("CR_SEAL_TOOL", image_tool.display().to_string()),
        ("CR_SEAL_KEY", image_key.display().to_string()),
        (
            "CR_SEAL_IMAGE_KEYS_DIR",
            image_keys_dir.display().to_string(),
        ),
        (
            "CR_SEAL_VERSION",
            release.map_or_else(|| dev_version(root), |r| r.version.clone()),
        ),
        ("CR_SEAL_BUILD", git_time(root).to_string()),
        ("CR_SEAL_CHANNEL", channel.clone()),
        ("CR_SEAL_KERNEL_VERSION", kernel_version(&defconfig_text)?),
        ("CR_SEAL_CONFIG_FORMAT", config_format(root)?.to_string()),
    ];
    let make = |targets: &[&str], parallel: &[String]| -> Result<(), String> {
        let mut cmd = Command::new("make");
        cmd.arg("-C")
            .arg(&d.buildroot)
            .arg(format!("O={}", d.out.display()));
        cmd.arg(format!("BR2_EXTERNAL={}", d.os.display()));
        cmd.arg(format!("COREROUTER_CARGO={}", cargo.display()));
        // The rustc next to that cargo. Without it cargo runs the rustup
        // proxy from each crate's directory, and a crate that ships a
        // `rust-toolchain` (dhcproto pins 1.90) switches the compiler in
        // the middle of the build (seen when the xtask ran without
        // `cargo xtask`, i.e. without RUSTUP_TOOLCHAIN).
        let rustc = cargo.with_file_name("rustc");
        if rustc.is_file() {
            cmd.env("RUSTC", rustc);
        }
        cmd.arg(format!("COREROUTER_WEB_DIR={}", web_dir.display()));
        cmd.arg(format!(
            "COREROUTER_FIRMWARE_STAGE={}",
            firmware_stage.display()
        ));
        cmd.arg(format!(
            "COREROUTER_CARGO_TARGET_DIR={}",
            d.top.join("cargo-target").display()
        ));
        // Buildroot: the variable overrides the defconfig's BR2_CCACHE_DIR.
        cmd.env("BR2_CCACHE_DIR", d.top.join("ccache"));
        if let Some(j) = &jobs {
            cmd.arg(format!("BR2_JLEVEL={j}"));
        }
        cmd.args(parallel);
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
        if only_crpkg {
            cmd.env("CR_ONLY_CRPKG", "1");
        }
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
    make(&[DEFCONFIG], &[])?;
    // A custom kernel version is in BR_NO_CHECK_HASH_FOR (linux.mk):
    // Buildroot checks it only while linux.hash is there. Checked here too,
    // so deleting that file can never let an unchecked kernel in.
    make(&["linux-source"], &[])?;
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
    make(
        &["corerouter-dirclean", "corerouter-firmware-dirclean"],
        &[],
    )?;
    // G1.6c: the installer kernel embeds the init: rebuilt after it
    // (kbuild relinks the initramfs and vmlinux only).
    let installer_dir = d.out.join("build").join(format!(
        "corerouter-installer-{}",
        kernel_version(&defconfig_text)?
    ));
    // G1.6e: `--only crpkg` leaves it (and the ISO) as they are.
    if !only_crpkg {
        for stamp in [".stamp_built", ".stamp_images_installed"] {
            let _ = std::fs::remove_file(installer_dir.join(stamp));
        }
    }
    // G1.6m: Buildroot applies `os/patches/linux/*.patch` only when it
    // extracts the kernel: changed patches need `linux-dirclean` (then a
    // full kernel build).
    // G1.6ze: the installer's kernel takes the same patches; a tree
    // extracted without them (before this) goes too.
    let (kpatch_files, kpatches) = patches_in(&d.os.join("patches/linux"))?;
    let kstamp = d.out.join(".corerouter-linux-patches.sha256");
    let changed = std::fs::read_to_string(&kstamp).ok().as_deref() != Some(kpatches.as_str());
    let kernel_trees = [
        (
            d.out.join("build").join(format!("linux-{version}")),
            "linux-dirclean",
        ),
        (installer_dir.clone(), "corerouter-installer-dirclean"),
    ];
    for (tree, dirclean) in &kernel_trees {
        if tree.exists() && (changed || !patches_missing(tree, &kpatch_files).is_empty()) {
            make(&[dirclean], &[])?;
        }
    }
    if changed {
        std::fs::write(&kstamp, &kpatches).map_err(|e| format!("{}: {e}", kstamp.display()))?;
    }
    // G3.4l: the same for `os/patches/frr/*.patch` (the ospfd TI-LFA fix):
    // a changed patch needs `frr-dirclean`.
    let (_, fpatches) = patches_in(&d.os.join("patches/frr"))?;
    let fstamp = d.out.join(".corerouter-frr-patches.sha256");
    if std::fs::read_to_string(&fstamp).ok().as_deref() != Some(fpatches.as_str()) {
        let built = std::fs::read_dir(d.out.join("build")).is_ok_and(|rd| {
            rd.flatten().any(|e| {
                e.file_name()
                    .to_str()
                    .is_some_and(|n| n.starts_with("frr-"))
            })
        });
        if built {
            make(&["frr-dirclean"], &[])?;
        }
        std::fs::write(&fstamp, &fpatches).map_err(|e| format!("{}: {e}", fstamp.display()))?;
    }
    // Buildroot reads the kernel fragment only when it configures the
    // kernel: a changed fragment needs `linux-reconfigure` (the kernel's
    // own make is incremental underneath).
    let fragment_hash = format!(
        "{} {} {}",
        sha256_file(&d.os.join("board/x86_64/linux.fragment"))?,
        sha256_file(&d.os.join("board/x86_64/nics.fragment"))?,
        sha256_file(&d.os.join("board/x86_64/installer.fragment"))?,
    );
    let stamp = d.out.join(".corerouter-linux-fragment.sha256");
    if std::fs::read_to_string(&stamp).ok().as_deref() != Some(fragment_hash.as_str()) {
        // G1.6j: a driver taken off the list must leave the image too, and
        // the target only gains files (below). The kernel installs them again.
        let mut old_modules = vec![d.out.join("target/lib/modules")];
        if let Ok(pkgs) = std::fs::read_dir(d.out.join("per-package")) {
            old_modules.extend(pkgs.flatten().map(|p| p.path().join("target/lib/modules")));
        }
        for dir in old_modules.iter().filter(|p| p.exists()) {
            std::fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        }
        if d.out
            .join("build")
            .join(format!("linux-{version}/.config"))
            .exists()
        {
            make(&["linux-reconfigure"], &[])?;
        }
        // The installer's .config comes from the image's and its fragment;
        // only its build stamp goes on every build, so this one goes here.
        let _ = std::fs::remove_file(
            d.out
                .join("build")
                .join(format!("corerouter-installer-{version}/.stamp_configured")),
        );
        std::fs::write(&stamp, &fragment_hash).map_err(|e| format!("{}: {e}", stamp.display()))?;
    }
    // G1.6o: with per-package directories the final target only gains
    // files (rsync without delete), and the packages built after ours keep
    // a copy of its files: GUI files of an older build (names carry a
    // content hash) would pile up in the image. Every copy goes; ours is
    // installed again from <out>/web.
    // G1.6j: the same for the firmware of an older firmware.lock.
    let mut stale = Vec::new();
    for tree in [
        "usr/share/corerouter/web",
        "lib/firmware",
        "usr/share/licenses/firmware",
    ] {
        let tree = Path::new(tree);
        stale.push(d.out.join("target").join(tree));
        if let Ok(pkgs) = std::fs::read_dir(d.out.join("per-package")) {
            stale.extend(pkgs.flatten().map(|p| p.path().join("target").join(tree)));
        }
    }
    for dir in stale.iter().filter(|p| p.exists()) {
        std::fs::remove_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    // processo: packages in parallel (BR2_PER_PACKAGE_DIRECTORIES makes it
    // safe; a package that cannot build in parallel still runs its own make
    // with -j1). Serial, the configure steps ran one after another.
    let top = match &top_jobs {
        Some(j) => vec![format!("-j{j}")],
        None => {
            let (j, cpus) = out::auto_top_jobs();
            eprintln!("   make all: -j{j} -l{cpus} (automatic; --top-jobs N sets it)");
            vec![format!("-j{j}"), format!("-l{cpus}")]
        }
    };
    make(&["all"], &top)?;
    for (tree, _) in &kernel_trees {
        let missing = patches_missing(tree, &kpatch_files);
        if !missing.is_empty() {
            return Err(format!(
                "{}: built without os/patches/linux/{}",
                tree.display(),
                missing.join(", ")
            ));
        }
    }

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
    let nics = std::fs::read_to_string(d.os.join("board/x86_64/nics.fragment"))
        .map_err(|e| e.to_string())?;
    // A driver of the wide list may be built in by linux.fragment, not less.
    let wide = module_symbols(&nics);
    let dropped: Vec<&str> = wide
        .into_iter()
        .filter(|s| {
            !kc.lines()
                .any(|l| l == format!("{s}=m") || l == format!("{s}=y"))
        })
        .collect();
    if !dropped.is_empty() {
        return Err(format!(
            "the kernel config dropped drivers of nics.fragment (a new kernel? see docs/os-image.md): {}",
            dropped.join(" ")
        ));
    }
    let lost: Vec<&str> = REQUIRED_MODULES
        .iter()
        .chain(SENSOR_MODULES.iter().map(|(symbol, _)| symbol))
        .filter(|s| !kc.lines().any(|l| l == format!("{s}=m")))
        .copied()
        .collect();
    if !lost.is_empty() {
        return Err(format!(
            "the kernel config lost the modules: {}",
            lost.join(" ")
        ));
    }
    if let Some(on) = kernel_on(&kc, KERNEL_OFF) {
        return Err(format!("the kernel config has {on}, which must be off"));
    }
    if let Some(lost) = KERNEL_VALUES.iter().find(|v| !kc.lines().any(|l| l == **v)) {
        return Err(format!("the kernel config lost '{lost}'"));
    }
    let libs = check_needed(&d.out.join("target"))?;
    let fw = firmware::verify(&d.os, &d.out.join("target"))?;
    eprintln!("   firmware: {fw} files, hashes and what the drivers declare checked");
    let images = d.out.join("images");
    if only_crpkg {
        eprintln!(
            "\nupdate package only (--only crpkg: disk.img, the ISO and the VM images were not rebuilt):"
        );
        for f in ["corerouter.crpkg", "bzImage", "rootfs.img"] {
            let p = images.join(f);
            let len = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
            eprintln!(
                "  {f:<30} {:>8.1} MiB  sha256 {}",
                len as f64 / 1048576.0,
                sha256_file(&p).unwrap_or_default()
            );
        }
        eprintln!(
            "  built in {:.1} s → {}",
            started.elapsed().as_secs_f64(),
            images.join("corerouter.crpkg").display()
        );
        return Ok(());
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
    if let Some(on) = kernel_on(&ic, KERNEL_OFF).or_else(|| kernel_on(&ic, INSTALLER_OFF)) {
        return Err(format!(
            "the installer kernel config has {on}, which must be off"
        ));
    }
    // G1.6zi: the ISO must boot, and see the disk, where the image does.
    if let Some(lost) = HARDWARE_COVERAGE
        .iter()
        .map(|s| format!("{s}=y"))
        .chain(KERNEL_VALUES.iter().map(|v| (*v).to_owned()))
        .find(|want| !ic.lines().any(|l| l == want))
    {
        return Err(format!("the installer kernel config lost '{lost}'"));
    }
    let boot = std::fs::metadata(images.join("installer/EFI/BOOT/BOOTX64.EFI"))
        .map(|m| m.len())
        .unwrap_or(0);
    if boot + (1 << 20) > MAX_BOOT_IMAGE {
        return Err(format!(
            "the installer kernel ({boot} bytes) does not fit the boot image"
        ));
    }
    // G1.6zf: the live image looks for the motherboard's sensor chip too.
    let live_required: Vec<&str> = REQUIRED_MODULE_FILES
        .iter()
        .copied()
        .chain(SENSOR_MODULES.iter().map(|(_, module)| *module))
        .collect();
    let (mods, mods_size) = livemods::verify(&installer_dir, &version, &live_required)?;
    eprintln!(
        "   live modules: {mods} modules of {version}{}, {:.1} MiB raw",
        livemods::SUFFIX,
        mods_size as f64 / 1048576.0
    );
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
        "live-modules.img",
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
    // The libraries are compared by canonical path: an out directory
    // reached through a symlink would otherwise miss every one.
    let target =
        &std::fs::canonicalize(target).map_err(|e| format!("{}: {e}", target.display()))?;
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
        .arg(&d.top)
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
    /// G1.6zi: how many CPUs the machine has (2). Above 255 it gets an IOMMU
    /// with interrupt remapping, as a real machine of that size has.
    smp: u32,
    /// G1.30: boot with two simulated radios (`corerouter.hwsim=2`) and
    /// wait for the init to say the Wi-Fi stack took them.
    wifi: bool,
}

fn parse_boot_args(args: &[String]) -> Result<BootArgs, String> {
    let mut b = BootArgs {
        efi: false,
        tcg: false,
        timeout: Duration::from_secs(120),
        append: String::new(),
        keep_config: false,
        smp: 2,
        wifi: false,
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--efi" => b.efi = true,
            "--tcg" => b.tcg = true,
            "--keep-config" => b.keep_config = true,
            "--wifi" => b.wifi = true,
            "--timeout" => {
                let v = it.next().ok_or("--timeout needs seconds")?;
                b.timeout = Duration::from_secs(
                    v.parse()
                        .map_err(|_| format!("--timeout {v}: not a number"))?,
                );
            }
            "--append" => b.append = it.next().ok_or("--append needs kernel arguments")?.clone(),
            "--smp" => {
                let v = it.next().ok_or("--smp needs a number of CPUs")?;
                b.smp = v
                    .parse()
                    .ok()
                    .filter(|n| (1..=MAX_TEST_CPUS).contains(n))
                    .ok_or_else(|| format!("--smp {v}: 1..={MAX_TEST_CPUS}"))?;
            }
            other => return Err(format!("unknown argument '{other}'\n{USAGE}")),
        }
    }
    if b.wifi && b.efi {
        return Err(
            "--wifi needs the kernel command line, which --efi cannot change (it is built in)"
                .into(),
        );
    }
    Ok(b)
}

/// The most CPUs `boot-test --smp` gives the machine (KVM's own limit on
/// x86 is 1024; each one is a host thread while the guest boots).
const MAX_TEST_CPUS: u32 = 1024;
/// A machine with an APIC id of 255 or more: only x2APIC reaches it, and on
/// real hardware x2APIC needs interrupt remapping.
const X2APIC_ONLY_CPUS: u32 = 255;

/// The machine of `boot-test`: `-machine`, `-cpu`, `-smp`, `-m` and, for a
/// big one, the IOMMU. G1.6zi: with more than 255 CPUs the guest is told
/// nothing a real machine would not be (`kvm-msi-ext-dest-id=off`: no
/// extended MSI destination), so the kernel needs `IRQ_REMAP` to start the
/// CPUs past APIC id 254, as on a real server.
fn boot_machine(kvm: bool, smp: u32) -> Vec<String> {
    let big = smp > X2APIC_ONLY_CPUS;
    let accel = if kvm { "kvm" } else { "tcg" };
    let split = if big { ",kernel-irqchip=split" } else { "" };
    let cpu = match (kvm, big) {
        (true, true) => "host,kvm-msi-ext-dest-id=off",
        (true, false) => "host",
        (false, _) => "max",
    };
    // 1 GiB for the usual two; a big machine's per-CPU areas need more.
    let mem = if smp > 8 {
        1024 + 16 * u64::from(smp)
    } else {
        1024
    };
    let mut a: Vec<String> = [
        "-machine",
        &format!("q35,accel={accel}{split}"),
        "-cpu",
        cpu,
        "-smp",
        &smp.to_string(),
        "-m",
        &mem.to_string(),
    ]
    .map(str::to_owned)
    .to_vec();
    if big {
        a.extend(["-device", "intel-iommu,intremap=on,eim=on"].map(str::to_owned));
    }
    a
}
/// G1.30: what the init says when `corerouter.hwsim=2` gave it two radios
/// (cfg80211, mac80211 and the simulated driver loaded from the image).
const WIFI_RADIOS: &str = "corerouter-init: wifi: 2 test radios";

/// What the serial console said, as the test reads it.
#[derive(Default, Debug, PartialEq)]
struct Report {
    /// Seconds from kernel start to the first `pong` (from init's line).
    ready_kernel_s: Option<f64>,
    idle_kib: Option<u64>,
}

/// A console line without its colour (G1.6zg): the SGR sequences
/// (`ESC [ … m`) the image's consoles send by default are dropped, so the
/// tests match the text a person reads. Anything else stays (the firmware's
/// and GRUB's cursor sequences were always there).
pub(crate) fn console_text(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(i) = rest.find("\u{1b}[") {
        let (before, seq) = rest.split_at(i);
        out.push_str(before);
        let params = seq.get(2..).unwrap_or("");
        let end = params
            .find(|c: char| !(c.is_ascii_digit() || c == ';'))
            .unwrap_or(params.len());
        if params.get(end..).is_some_and(|r| r.starts_with('m')) {
            rest = params.get(end + 1..).unwrap_or("");
        } else {
            out.push_str("\u{1b}[");
            rest = params;
        }
    }
    out.push_str(rest);
    out
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
    let top = out_dir(root)?;
    let images = dirs(root, &top, &lock).out.join("images");
    let disk = images.join("disk.img");
    if !disk.exists() {
        return Err(format!(
            "{} missing: run `cargo xtask os build` first",
            disk.display()
        ));
    }
    let kvm = !b.tcg && kvm_usable();
    let port = free_port()?;
    let web_port = free_port()?;
    let log_path = top.join("boot-test.log");
    let mon = top.join("boot-test.monitor");
    let _ = std::fs::remove_file(&mon);
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args(boot_machine(kvm, b.smp));
    cmd.args(["-display", "none", "-serial", "stdio", "-no-reboot"]);
    cmd.arg("-monitor")
        .arg(format!("unix:{},server=on,wait=off", mon.display()));
    cmd.args(hotplug::QEMU_ARGS);
    // G1.6zf: a second disk, NVMe, only to be read: its temperature must be
    // in `system.health.print` (QEMU's says 50 °C).
    let nvme = top.join("boot-test-nvme.raw");
    std::fs::File::create(&nvme)
        .and_then(|f| f.set_len(16 << 20))
        .map_err(|e| format!("{}: {e}", nvme.display()))?;
    cmd.arg("-drive").arg(format!(
        "file={},if=none,id=sensor0,format=raw",
        nvme.display()
    ));
    cmd.args(["-device", "nvme,drive=sensor0,serial=CRSENSOR0"]);
    let snapshot = if b.keep_config { "" } else { ",snapshot=on" };
    cmd.arg("-drive").arg(format!(
        "file={},if=virtio,format=raw{snapshot}",
        disk.display()
    ));
    cmd.args(["-device", "virtio-rng-pci"]);
    cmd.arg("-netdev").arg(format!(
        "user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:{GUEST_TLS_PORT},\
         hostfwd=tcp:127.0.0.1:{web_port}-:{GUEST_WEB_PORT}"
    ));
    cmd.args(["-device", "virtio-net-pci,netdev=n0"]);
    let vars = top.join("OVMF_VARS.fd");
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
        let hwsim = if b.wifi { " corerouter.hwsim=2" } else { "" };
        cmd.arg("-append")
            .arg(format!("{GUEST_IP_ARG} {}{hwsim}", b.append).trim_end());
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
    let res = watch(&mut child, &b, (port, web_port), started, &log_path, &mon).and_then(|r| {
        // With --efi the guest has no address (the built-in command line).
        let seen = if b.efi {
            let skipped = "skipped: no address with --efi".to_owned();
            (skipped.clone(), skipped)
        } else {
            (
                cpus_check(root, &top, port, b.smp)?,
                sensors_check(root, &top, port)?,
            )
        };
        Ok((r, seen))
    });
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_file(&vars);
    let _ = std::fs::remove_file(&mon);
    let _ = std::fs::remove_file(&nvme);
    let ((report, wall_ready, ping, web, hot), (cpus, sensors)) = res?;
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
    eprintln!("  web access (https://…/, the .wasm, WebSocket login):");
    for l in web.lines() {
        eprintln!("    {l}");
    }
    eprintln!("  cards plugged in after boot (G1.6n, G1.6j): {hot}");
    eprintln!("  sensors (G1.6zf):                   {sensors}");
    eprintln!("  CPUs (G1.6zi):                      {cpus}");
    if let Some(kib) = report.idle_kib {
        eprintln!(
            "  idle memory in use:                 {:.1} MiB",
            kib as f64 / 1024.0
        );
    }
    Ok(())
}

/// `corerouter-cli run` on the booted image, as `admin` over TLS (no password
/// on a first boot).
fn guest_cli(root: &Path, top: &Path, port: u16, id: &str) -> Result<String, String> {
    let cli = push::cli(root)?;
    let home = top.join("boot-test-home");
    let who = install::Admin {
        home: &home,
        password: "",
        strict: false,
    };
    let out = install::cli_run(&cli, &who, port, id, "{}");
    let _ = std::fs::remove_dir_all(&home);
    out
}

/// G1.6zi: the router uses every CPU the machine has (`system.resource.print`
/// counts the ones the kernel brought up). 64 was the limit, and past APIC id
/// 254 a kernel without interrupt remapping leaves the rest stopped.
fn cpus_check(root: &Path, top: &Path, port: u16, want: u32) -> Result<String, String> {
    let got = guest_cli(root, top, port, "system.resource.print")?;
    let v: serde_json::Value =
        serde_json::from_str(got.trim()).map_err(|e| format!("system.resource.print: {e}"))?;
    match v.get("cpu_count").and_then(serde_json::Value::as_u64) {
        Some(n) if n == u64::from(want) => Ok(format!("{n} of {want} in use")),
        n => Err(format!(
            "G1.6zi: the machine has {want} CPUs and the router uses {} (NR_CPUS, IRQ_REMAP?)",
            n.map_or_else(|| "?".to_owned(), |n| n.to_string())
        )),
    }
}

/// G1.6zf: the image reads the temperature of what the machine has. QEMU has
/// no CPU sensor, and its NVMe disk has one: `system.health.print`, asked as
/// an operator does (`admin` over TLS), must list it.
fn sensors_check(root: &Path, top: &Path, port: u16) -> Result<String, String> {
    // The first reading is the health service's, seconds after ready.
    let deadline = Instant::now() + Duration::from_secs(30);
    let got = loop {
        let got = guest_cli(root, top, port, "system.health.print").unwrap_or_else(|e| e);
        let found = disk_temperatures(&got);
        if !found.is_empty() || Instant::now() >= deadline {
            break (found, got);
        }
        std::thread::sleep(Duration::from_millis(500));
    };
    match got {
        (found, _) if !found.is_empty() => Ok(found.join(", ")),
        (_, text) => Err(format!(
            "G1.6zf: system.health.print has no temperature of the NVMe disk (CONFIG_NVME_HWMON off?): {}",
            text.chars().take(600).collect::<String>()
        )),
    }
}

/// The NVMe temperatures of a `system.health.print` answer that make sense
/// (QEMU's disk says 50 °C), as `chip label value`.
fn disk_temperatures(answer: &str) -> Vec<String> {
    let rows: Vec<serde_json::Value> = serde_json::from_str(answer.trim()).unwrap_or_default();
    rows.iter()
        .filter(|r| r["type"] == "temperature")
        .filter_map(|r| {
            let chip = r["chip"].as_str().filter(|c| c.starts_with("nvme"))?;
            let value = r["value"].as_f64().filter(|v| (1.0..=120.0).contains(v))?;
            Some(format!(
                "{chip} {} {value} °C",
                r["label"].as_str().unwrap_or_default()
            ))
        })
        .collect()
}

fn watch(
    child: &mut Child,
    b: &BootArgs,
    (port, web_port): (u16, u16),
    started: Instant,
    log_path: &Path,
    mon: &Path,
) -> Result<(Report, Duration, String, String, String), String> {
    let stdout = child.stdout.take().ok_or("qemu: no stdout")?;
    let (tx, rx) = mpsc::channel::<String>();
    std::thread::Builder::new()
        .name("qemu-serial".into())
        .spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if tx.send(console_text(&line)).is_err() {
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
    let mut web = None;
    let mut boot_driver = false;
    let wifi = std::cell::Cell::new(false);
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
                "skipped: with --efi the command line is the built-in one, no address on ether1 (G1.6d)".to_owned()
            } else {
                tls_ping(port)?
            });
            web = Some(if b.efi {
                "skipped: no address with --efi".to_owned()
            } else {
                web_check(web_port)?
            });
        }
        if let Some(k) = parse_idle(&line) {
            report.idle_kib = Some(k);
        }
        boot_driver |= hotplug::boot_driver(&line);
        if line.contains(WIFI_RADIOS) {
            wifi.set(true);
        }
        if let (Some(w), Some(p), Some(_), Some(web)) = (wall_ready, &ping, report.idle_kib, &web) {
            if !boot_driver {
                return Err(format!(
                    "G1.6j: the driver of the card present at boot (e100) did not load (console in {})",
                    log_path.display()
                ));
            }
            let mut wait_line = |want: &dyn Fn(&str) -> bool, max: Duration| {
                let until = Instant::now() + max;
                loop {
                    let left = until.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Err(format!(
                            "no such console line (console in {})",
                            log_path.display()
                        ));
                    }
                    match rx.recv_timeout(left) {
                        Ok(line) => {
                            let _ = writeln!(log, "{line}");
                            if line.contains("corerouter-init") {
                                eprintln!("  | {line}");
                            }
                            if line.contains(WIFI_RADIOS) {
                                wifi.set(true);
                            }
                            if want(&line) {
                                return Ok(());
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        Err(mpsc::RecvTimeoutError::Disconnected) => {
                            return Err("qemu exited".into());
                        }
                    }
                }
            };
            let hot = hotplug::check(mon, &mut wait_line)?;
            if b.wifi && !wifi.get() {
                wait_line(&|l| l.contains(WIFI_RADIOS), Duration::from_secs(20)).map_err(|e| {
                    format!("G1.30: the simulated radios did not come up (corerouter.hwsim=2): {e}")
                })?;
            }
            return Ok((report, w, p.clone(), web.clone(), hot));
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

/// G1.6o: what a browser does at `https://<router>/`, through QEMU's port
/// forward (certificate not checked, as `tls_ping`): the page, the `.wasm`
/// it names, then a WebSocket on `/ws` and `auth.login` as `admin` with the
/// empty password of a new router. A new router refuses that login from the
/// network until a password is set (G0.3b): either answer proves the
/// channel works end to end.
fn web_check(port: u16) -> Result<String, String> {
    let files = web_files(port)?;
    let login = ws_login(port)?;
    Ok(format!("{files}\nwss /ws auth.login: {login}"))
}

/// The GUI's page and its wasm over HTTPS.
fn web_files(port: u16) -> Result<String, String> {
    let base = format!("https://127.0.0.1:{port}");
    // The daemon may open 443 a tick after it answers the TLS ping.
    let mut page = String::new();
    for _ in 0..20 {
        let out = Command::new("curl")
            .args(["-skf", "--max-time", "10"])
            .arg(format!("{base}/"))
            .output()
            .map_err(|e| format!("curl: {e}"))?;
        if out.status.success() {
            page = String::from_utf8_lossy(&out.stdout).into_owned();
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    if !page.contains("<canvas") {
        return Err(format!("web: GET {base}/ gave no GUI page"));
    }
    let wasm = wasm_name(&page).ok_or("web: the page names no .wasm")?;
    let out = Command::new("curl")
        // As a browser: the image keeps the wasm only gzip-compressed.
        .args([
            "-skf",
            "--compressed",
            "--max-time",
            "60",
            "-o",
            "/dev/null",
            "-w",
        ])
        .arg("%{http_code} %{content_type} %{size_download} %{time_total}")
        .arg(format!("{base}/{wasm}"))
        .output()
        .map_err(|e| format!("curl: {e}"))?;
    let got = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut f = got.split_whitespace();
    let (code, mime, size, secs) = (f.next(), f.next(), f.next(), f.next());
    if code != Some("200") || mime != Some("application/wasm") {
        return Err(format!("web: GET /{wasm}: {got}"));
    }
    let size: u64 = size.and_then(|s| s.parse().ok()).unwrap_or(0);
    Ok(format!(
        "GET / ok ({} bytes)\nGET /{wasm}: {:.1} MiB on the wire (gzip) in {} s",
        page.len(),
        size as f64 / 1048576.0,
        secs.unwrap_or("?")
    ))
}

/// The `…_bg.wasm` file a trunk page preloads.
fn wasm_name(page: &str) -> Option<String> {
    let end = page.find(".wasm")?;
    let start = page.get(..end)?.rfind(['"', '\'', '/'])? + 1;
    page.get(start..end + 5).map(str::to_owned)
}

/// A WebSocket handshake and one `auth.login` frame over `openssl
/// s_client` (no WebSocket or TLS crate in xtask); the answer's text.
fn ws_login(port: u16) -> Result<String, String> {
    let login = br#"{"id":1,"method":"auth.login","params":{"user":"admin","password":""}}"#;
    // G1.6j: `hotplug.rs`'s i82551. Its driver opens the port only with its
    // firmware, so this answers whether the kernel reads `/lib/firmware`.
    let req = format!(
        "GET /ws HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n"
    );
    let frame = ws_client_frame(login)?;
    let mut child = Command::new("openssl")
        .args(["s_client", "-quiet", "-ign_eof", "-connect"])
        .arg(format!("127.0.0.1:{port}"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("openssl: {e}"))?;
    let mut stdin = child.stdin.take().ok_or("openssl: no stdin")?;
    let _ = stdin.write_all(req.as_bytes());
    let _ = stdin.flush();
    let mut stdout = child.stdout.take().ok_or("openssl: no stdout")?;
    // What came so far, after each read; the frame goes only after the
    // `101` (a client must not send before the handshake answer, RFC 6455
    // §4.1, and tungstenite refuses it).
    let (tx, rx) = mpsc::channel::<Vec<u8>>();
    let _ = std::thread::Builder::new()
        .name("ws-login".into())
        .spawn(move || {
            use std::io::Read;
            let mut got = Vec::new();
            let mut buf = [0u8; 4096];
            while let Ok(n) = stdout.read(&mut buf) {
                if n == 0 {
                    break;
                }
                got.extend_from_slice(buf.get(..n).unwrap_or_default());
                if tx.send(got.clone()).is_err() {
                    break;
                }
            }
        });
    let until = Instant::now() + Duration::from_secs(10);
    let mut sent = false;
    let mut up_sent = false;
    let mut got = Vec::new();
    let done = loop {
        let left = until.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(g) => got = g,
            Err(_) => break false,
        }
        if !got.windows(4).any(|w| w == b"\r\n\r\n") {
            continue;
        }
        if !got.starts_with(b"HTTP/1.1 101") {
            break true;
        }
        let texts = ws_texts(&got);
        if let Some(first) = texts.first() {
            if !first.contains("\"token\"") || texts.iter().any(|t| t.contains("\"id\":2")) {
                break true;
            }
            if !up_sent {
                // The session token travels next to `id` and `method`
                // (`docs/control-protocol.md`).
                let answer: serde_json::Value =
                    serde_json::from_str(first).map_err(|e| format!("web: {e}"))?;
                let bring_up = serde_json::json!({
                    "id": 2,
                    "method": "engine.execute",
                    "params": {"command": "interface.set",
                               "params": {"name": "ether2", "disabled": false}},
                    "token": answer.pointer("/result/token"),
                });
                let up_frame = ws_client_frame(bring_up.to_string().as_bytes())?;
                let _ = stdin.write_all(&up_frame);
                let _ = stdin.flush();
                up_sent = true;
            }
        }
        if !sent {
            let _ = stdin.write_all(&frame);
            let _ = stdin.flush();
            sent = true;
        }
    };
    drop(stdin);
    let _ = child.kill();
    let _ = child.wait();
    let got = if done || !got.is_empty() {
        Ok(got)
    } else {
        Err(())
    };
    let got = got.map_err(|_| "web: no WebSocket answer in 10 s")?;
    if !got.starts_with(b"HTTP/1.1 101") {
        let head: String = String::from_utf8_lossy(&got).chars().take(120).collect();
        return Err(format!("web: WebSocket handshake refused: {head}"));
    }
    let texts = ws_texts(&got);
    let text = texts
        .first()
        .ok_or("web: no text frame after the handshake")?;
    if text.contains("\"token\"") {
        let up = texts.iter().find(|t| t.contains("\"id\":2"));
        match up {
            Some(t) if t.contains("\"ok\":true") => {
                Ok("logged in; ether2 (e100, opens only with its firmware) brought up".into())
            }
            Some(t) => Err(format!("G1.6j: firmware from /lib/firmware: {t}")),
            None => Err("G1.6j: no answer to interface.set on ether2 in 10 s".into()),
        }
    } else if text.contains("no password") {
        Ok(format!(
            "answered, refused as expected for a new router: {}",
            text.chars().take(160).collect::<String>()
        ))
    } else {
        Err(format!("web: unexpected login answer {text}"))
    }
}

/// A masked text frame, what a client sends (RFC 6455 §5.3).
fn ws_client_frame(text: &[u8]) -> Result<Vec<u8>, String> {
    let mask = [0x37u8, 0xfa, 0x21, 0x3d];
    let mut frame = vec![0x81];
    match text.len() {
        // Seven bits, or 126 and a 16-bit length (RFC 6455 §5.2).
        n @ 0..=125 => frame.push(0x80 | u8::try_from(n).map_err(|e| e.to_string())?),
        n => {
            let n = u16::try_from(n).map_err(|_| "frame too long for this test")?;
            frame.push(0x80 | 126);
            frame.extend(n.to_be_bytes());
        }
    }
    frame.extend(mask);
    frame.extend(text.iter().zip(mask.iter().cycle()).map(|(b, m)| b ^ m));
    Ok(frame)
}

/// The complete unmasked text frames after an HTTP head.
fn ws_texts(got: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let Some(at) = got.windows(4).position(|w| w == b"\r\n\r\n") else {
        return out;
    };
    let mut rest = got.get(at + 4..).unwrap_or_default();
    while let Some((text, next)) = ws_one_text(rest) {
        out.push(text);
        rest = next;
    }
    out
}

/// One text frame and what follows it. `None`: incomplete, or not text.
fn ws_one_text(frame: &[u8]) -> Option<(String, &[u8])> {
    let (op, len) = (*frame.first()?, *frame.get(1)?);
    if op != 0x81 {
        return None;
    }
    let (len, from) = match len & 0x7f {
        126 => (
            usize::from(u16::from_be_bytes([*frame.get(2)?, *frame.get(3)?])),
            4,
        ),
        127 => return None,
        n => (usize::from(n), 2),
    };
    let body = frame.get(from..from + len)?;
    Some((
        String::from_utf8_lossy(body).into_owned(),
        frame.get(from + len..)?,
    ))
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

    /// G1.6ze: the ISO's kernel listed `bond0`, `dummy0` and seven tunnels:
    /// its command line lacked the two parameters, and its tree the patches.
    #[test]
    fn both_kernels_keep_their_drivers_from_creating_devices() {
        let ok = "console=tty0 corerouter.mode=live bonding.max_bonds=0 dummy.numdummies=0 quiet";
        no_kernel_devices("x", ok).unwrap();
        for bad in [
            "",
            "console=tty0 corerouter.mode=live panic=10 quiet",
            "bonding.max_bonds=0 quiet",
            "bonding.max_bonds=1 dummy.numdummies=0",
            "xbonding.max_bonds=0 dummy.numdummies=01",
        ] {
            let e = no_kernel_devices("installer.fragment", bad).unwrap_err();
            assert!(
                e.starts_with("installer.fragment: CONFIG_CMDLINE needs '"),
                "{e}"
            );
        }
        for want in INSTALLER_KERNEL.iter().filter(|w| w.contains("CMDLINE")) {
            no_kernel_devices("INSTALLER_KERNEL", want.trim_end_matches('"')).unwrap();
        }
        let tree = std::env::temp_dir().join(format!("cr-xtask-patches-{}", std::process::id()));
        std::fs::create_dir_all(&tree).unwrap();
        let patches = [
            PathBuf::from("/os/patches/linux/0001-a.patch"),
            PathBuf::from("/os/patches/linux/0002-b.patch"),
        ];
        // No list at all (a tree Buildroot never patched), then an empty one
        // (what the installer's tree had), one patch, both.
        assert_eq!(patches_missing(&tree, &patches).len(), 2);
        let list = tree.join(".applied_patches_list");
        std::fs::write(&list, "").unwrap();
        assert_eq!(
            patches_missing(&tree, &patches),
            ["0001-a.patch", "0002-b.patch"]
        );
        std::fs::write(&list, "/elsewhere/os/patches/linux/0001-a.patch\n").unwrap();
        assert_eq!(patches_missing(&tree, &patches), ["0002-b.patch"]);
        std::fs::write(&list, "/x/0001-a.patch\n/x/0002-b.patch\n/x/0003-c.patch\n").unwrap();
        assert!(patches_missing(&tree, &patches).is_empty());
        assert!(patches_missing(&tree, &[]).is_empty());
        std::fs::remove_dir_all(&tree).unwrap();
    }

    /// G1.6zf: the sensors stay in the kernel, the Super-I/O drivers stay
    /// modules, and PID 1 loads the modules the kernel builds.
    #[test]
    fn sensors_built_in_and_super_io_as_modules() {
        let os = Path::new(env!("CARGO_MANIFEST_DIR")).join("../os");
        let fragment = std::fs::read_to_string(os.join("board/x86_64/linux.fragment")).unwrap();
        let init =
            std::fs::read_to_string(os.join("../apps/corerouter-init/src/modules.rs")).unwrap();
        assert_eq!(check_sensors(&fragment, &init).unwrap(), 10);
        let e = check_sensors(&fragment.replace("CONFIG_NVME_HWMON=y", ""), &init).unwrap_err();
        assert!(e.contains("CONFIG_NVME_HWMON=y is required"), "{e}");
        // Built in, a Super-I/O driver would probe on every machine and VM.
        let built_in = fragment.replace("CONFIG_SENSORS_IT87=m", "CONFIG_SENSORS_IT87=y");
        let e = check_sensors(&built_in, &init).unwrap_err();
        assert!(e.contains("CONFIG_SENSORS_IT87=m is required"), "{e}");
        let e = check_sensors(&fragment, &init.replace("\"it87\", ", "")).unwrap_err();
        assert!(e.contains("loads the sensor modules"), "{e}");
        let e = check_sensors(&fragment, "").unwrap_err();
        assert!(e.contains("no `pub const SENSOR_MODULES"), "{e}");
    }

    /// G1.6zi: every option the hardware coverage adopted is in the list the
    /// checks read, and the two EDAC drivers that write an error line on a
    /// machine without ECC memory stay out.
    #[test]
    fn every_adopted_kernel_option_has_its_check() {
        let os = Path::new(env!("CARGO_MANIFEST_DIR")).join("../os");
        let fragment = std::fs::read_to_string(os.join("board/x86_64/linux.fragment")).unwrap();
        let start = fragment
            .find("# --- Every core of a big machine (G1.6zi)")
            .unwrap();
        let end = fragment.find("# CONFIG_RAS_FMPM is not set").unwrap();
        let adopted = fragment_symbols(&fragment[start..end]);
        assert!(adopted.len() > 40, "{}", adopted.len());
        for symbol in &adopted {
            assert!(HARDWARE_COVERAGE.contains(symbol), "{symbol} has no check");
        }
        for symbol in HARDWARE_COVERAGE {
            assert!(
                adopted.contains(symbol),
                "{symbol} is checked and not in the section"
            );
        }
        for noisy in [
            "CONFIG_EDAC_IGEN6",
            "CONFIG_EDAC_PND2",
            "CONFIG_MEMORY_FAILURE",
        ] {
            assert!(!fragment.contains(&format!("{noisy}=")), "{noisy}");
        }
        for off in KERNEL_OFF {
            assert!(fragment.contains(&format!("# {off} is not set")), "{off}");
        }
    }

    /// G1.6zf: what `boot-test` wants from `system.health.print`.
    #[test]
    fn the_nvme_disks_temperature_is_found_in_the_answer() {
        let answer = r#"[
            {"name":"acpitz-temp1","chip":"acpitz","label":"temp1","type":"temperature","value":27.8},
            {"name":"nvme0-composite","chip":"nvme0","label":"Composite","type":"temperature","value":50.0,"crit":100.0},
            {"name":"nvme1-composite","chip":"nvme1","label":"Composite","type":"temperature","value":0.0},
            {"name":"nvme0-fan1","chip":"nvme0","label":"fan1","type":"fan","value":50.0}
        ]"#;
        assert_eq!(disk_temperatures(answer), ["nvme0 Composite 50 °C"]);
        // Before the first reading, an error text, a kernel without the driver.
        for none in [
            "[]",
            "",
            "error: connection refused",
            r#"[{"chip":"acpitz","type":"temperature","value":27.8}]"#,
        ] {
            assert!(disk_temperatures(none).is_empty(), "{none}");
        }
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
        assert_eq!(kernel_on(f, &["CONFIG_C", "CONFIG_AB"]), None);
        assert_eq!(kernel_on(f, &["CONFIG_C", "CONFIG_B"]), Some("CONFIG_B"));
        assert_eq!(kernel_on(f, &["CONFIG_A"]), Some("CONFIG_A"));
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
    fn console_lines_are_read_without_their_colour() {
        // What the image's consoles send (G1.6zg): SGR only, a reset at the
        // end of every span.
        assert_eq!(
            console_text("  \u{1b}[1;33mWARNING\u{1b}[0m  admin has \u{1b}[2mno\u{1b}[0m password"),
            "  WARNING  admin has no password"
        );
        assert_eq!(console_text("\u{1b}[32mOK\u{1b}[0m"), "OK");
        assert_eq!(console_text("\u{1b}[m"), "");
        // The firmware's cursor sequences and a cut one stay as they came.
        let fw = "\u{1b}[2J\u{1b}[01;01HBdsDxe: loading Boot0001";
        assert_eq!(console_text(fw), fw);
        assert_eq!(console_text("x\u{1b}[1;3"), "x\u{1b}[1;3");
        assert_eq!(
            console_text("corerouter-init: ready: 1 s"),
            "corerouter-init: ready: 1 s"
        );
    }

    #[test]
    fn web_check_parsing() {
        let page = r#"<link rel="preload" href="/corerouter-gui-1a2b_bg.wasm" as="fetch">"#;
        assert_eq!(
            wasm_name(page).as_deref(),
            Some("corerouter-gui-1a2b_bg.wasm")
        );
        let mut got = b"HTTP/1.1 101 Switching Protocols\r\n\r\n".to_vec();
        got.extend([0x81, 5]);
        got.extend(b"hello");
        assert_eq!(ws_texts(&got), ["hello"]);
        assert!(ws_texts(&got[..got.len() - 1]).is_empty());
        // Two frames in one read, then one cut short.
        let two = [got.as_slice(), &[0x81, 2], b"ok", &[0x81, 9], b"cut"].concat();
        assert_eq!(ws_texts(&two), ["hello", "ok"]);
        assert_eq!(ws_client_frame(b"abc").unwrap().len(), 2 + 4 + 3);
        assert_eq!(ws_client_frame(&[b'a'; 126]).unwrap().len(), 4 + 4 + 126);
        assert!(ws_client_frame(&vec![b'a'; 70_000]).is_err());
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
        // G1.6zi: a machine with more CPUs than the kernel used to take.
        assert_eq!(b.smp, 2);
        let big = parse_boot_args(&["--smp".into(), "300".into()]).unwrap();
        assert_eq!(big.smp, 300);
        for bad in ["0", "1025", "many", "-1"] {
            assert!(
                parse_boot_args(&["--smp".into(), bad.into()]).is_err(),
                "{bad}"
            );
        }
        assert!(parse_boot_args(&["--smp".into()]).is_err());
        let two = boot_machine(true, 2).join(" ");
        assert_eq!(two, "-machine q35,accel=kvm -cpu host -smp 2 -m 1024");
        let many = boot_machine(true, 128).join(" ");
        assert_eq!(many, "-machine q35,accel=kvm -cpu host -smp 128 -m 3072");
        // Past APIC id 254: an IOMMU that remaps interrupts, and no shortcut
        // a real machine does not have.
        let huge = boot_machine(true, 300).join(" ");
        assert!(huge.contains("kernel-irqchip=split"), "{huge}");
        assert!(huge.contains("-cpu host,kvm-msi-ext-dest-id=off"), "{huge}");
        assert!(
            huge.ends_with("-device intel-iommu,intremap=on,eim=on"),
            "{huge}"
        );
        assert!(
            boot_machine(false, 2)
                .join(" ")
                .contains("accel=tcg -cpu max")
        );
    }
}

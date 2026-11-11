//! G1.6zn: the system in RAM, and the system disk going away.
//!
//! With `system.boot.set {to_ram: yes}`, `corerouter-init` copies the
//! running slot's root to RAM at boot, reading it through the slot's
//! dm-verity device (so every block is checked against the signed root
//! hash of the command line, as a boot from the disk checks it), and runs
//! from there: a USB stick pulled out of the running router, or a USB SSD
//! that resets, no longer takes the system with it. Whatever the option,
//! a system disk that goes away is one clear line on the console, in the
//! router's log and in the health checks, and configuration changes are
//! refused with that line instead of a flood of I/O errors.
//!
//! Three small files carry it between the processes:
//!
//! - `<config>/package/boot.json` ([`BootOptions`]): the operator's choice,
//!   written by the daemon's package service from the running
//!   configuration and read by `corerouter-init` at the next boot. A file
//!   of its own and not `running.json`: commits go to a journal first
//!   (G0.22), and PID 1 reads a few bytes before anything runs.
//! - `<runtime>/root.json` ([`RootState`]): where this boot's root came
//!   from, written by `corerouter-init`, read by the package service.
//! - `<runtime>/system-disk-removed`: the line `corerouter-init` wrote when
//!   the disk went away; that the file exists is the state. The config
//!   storage refuses writes with its text, and the package service stops
//!   touching the disk.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{cmdline_value, verity};

/// In `<config>/package/`.
pub const OPTIONS_FILE: &str = "boot.json";
/// In the runtime directory (`/run/corerouter`).
pub const ROOT_FILE: &str = "root.json";
/// In the runtime directory.
pub const GONE_FILE: &str = "system-disk-removed";
/// Each of the files is a line or two; a bigger one is not ours.
const MAX_FILE: u64 = 4096;
/// Memory that must stay available once the root is in RAM. The router
/// idles at 110–130 MiB with FRR and a login takes ~50 MiB more (the
/// live image's numbers, G1.6y/G1.6za, **medido**); a machine with less
/// keeps its root on the disk.
pub const RAM_LEFT_KIB: u64 = 256 * 1024;
/// Largest root copied (a slot is 512 MiB; the root is 87 MiB, G1.6zd,
/// **medido**). Bounds what a wrong command line can ask for.
pub const MAX_ROOT_BYTES: u64 = 1 << 30;

/// What the next boot does with the root (`system.boot`).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootOptions {
    /// Copy the root to RAM and run from there.
    #[serde(default)]
    pub to_ram: bool,
}

/// `<config>/package/boot.json`.
pub fn options_path(config: &Path) -> PathBuf {
    config.join(crate::state::DIR).join(OPTIONS_FILE)
}

fn read_small(path: &Path) -> Result<Option<String>, String> {
    let f = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    let mut text = String::new();
    f.take(MAX_FILE)
        .read_to_string(&mut text)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(Some(text))
}

/// The options of the next boot. No file: the defaults (off).
pub fn load_options(config: &Path) -> Result<BootOptions, String> {
    let path = options_path(config);
    match read_small(&path)? {
        None => Ok(BootOptions::default()),
        Some(t) => serde_json::from_str(&t).map_err(|e| format!("{}: {e}", path.display())),
    }
}

/// Written so a power cut right after leaves the old file or the new one:
/// temporary file, fsync, rename, fsync of the directory.
fn write_durable(path: &Path, text: &str) -> Result<(), String> {
    let err = |e: std::io::Error| format!("{}: {e}", path.display());
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(err)?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = File::create(&tmp).map_err(err)?;
    f.write_all(text.as_bytes()).map_err(err)?;
    f.sync_all().map_err(err)?;
    fs::rename(&tmp, path).map_err(err)?;
    if let Some(dir) = path.parent() {
        File::open(dir).and_then(|d| d.sync_all()).map_err(err)?;
    }
    Ok(())
}

/// Keeps `o` for the next boot.
pub fn save_options(config: &Path, o: BootOptions) -> Result<(), String> {
    let text = serde_json::to_string(&o).map_err(|e| e.to_string())?;
    write_durable(&options_path(config), &format!("{text}\n"))
}

/// Where this boot's root came from.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootState {
    /// The root runs from RAM (the system disk can go).
    pub in_ram: bool,
    /// Bytes copied to RAM.
    #[serde(default)]
    pub bytes: u64,
    /// How long the copy (with its dm-verity check) took.
    #[serde(default)]
    pub copy_ms: u64,
    /// The system disk (`sda`, `nvme0n1`): the one that holds `/config`.
    #[serde(default)]
    pub disk: Option<String>,
    /// Why the root stayed on the disk although the RAM was asked for.
    #[serde(default)]
    pub note: Option<String>,
}

/// `<runtime>/root.json`, when this boot wrote one.
pub fn read_root(runtime: &Path) -> Option<RootState> {
    let text = read_small(&runtime.join(ROOT_FILE)).ok()??;
    serde_json::from_str(&text).ok()
}

pub fn write_root(runtime: &Path, s: &RootState) -> Result<(), String> {
    let text = serde_json::to_string(s).map_err(|e| e.to_string())?;
    let path = runtime.join(ROOT_FILE);
    fs::write(&path, format!("{text}\n")).map_err(|e| format!("{}: {e}", path.display()))
}

/// The line of a system disk that went away: the console, the router's log
/// and every refused write say it.
pub fn gone_line(disk: &str, in_ram: bool) -> String {
    if in_ram {
        format!(
            "system disk {disk} removed: the router keeps running from RAM, but configuration changes are no longer saved; reboot with the disk in place"
        )
    } else {
        format!(
            "system disk {disk} removed: the system runs from that disk and may stop at any moment, and configuration changes are no longer saved; reboot with the disk in place"
        )
    }
}

/// The line, when the system disk went away during this boot.
pub fn read_gone(runtime: &Path) -> Option<String> {
    read_small(&runtime.join(GONE_FILE))
        .ok()
        .flatten()
        .map(|t| t.trim().to_owned())
}

pub fn write_gone(runtime: &Path, line: &str) -> Result<(), String> {
    let path = runtime.join(GONE_FILE);
    fs::write(&path, format!("{line}\n")).map_err(|e| format!("{}: {e}", path.display()))
}

/// `MemAvailable` of `/proc/meminfo`, in KiB.
pub fn mem_available_kib(meminfo: &str) -> Option<u64> {
    meminfo
        .lines()
        .find_map(|l| l.strip_prefix("MemAvailable:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// Whether `bytes` of root fit in RAM with [`RAM_LEFT_KIB`] to spare.
pub fn ram_check(meminfo: &str, bytes: u64) -> Result<(), String> {
    let avail = mem_available_kib(meminfo).ok_or("no MemAvailable in /proc/meminfo")?;
    let need = bytes / 1024 + RAM_LEFT_KIB;
    if avail < need {
        return Err(format!(
            "{} MiB of RAM available, {} MiB needed ({} MiB of root and {} MiB for the router)",
            avail / 1024,
            need / 1024,
            bytes >> 20,
            RAM_LEFT_KIB / 1024
        ));
    }
    Ok(())
}

/// The running root's dm-verity device, from the command line the boot
/// entry gave the kernel (`root=/dev/dm-0`, `dm-mod.create=…`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerityRoot {
    pub device: String,
    pub data_blocks: u64,
    pub root_hash: String,
}

impl VerityRoot {
    pub fn bytes(&self) -> u64 {
        self.data_blocks.saturating_mul(verity::BLOCK as u64)
    }
}

/// The root's verity device and size. `Err`: the root is not checked by
/// dm-verity (the fallback path's built-in `root=PARTUUID=`), so there is
/// nothing to copy that a check vouches for.
pub fn verity_root(cmdline: &str) -> Result<VerityRoot, String> {
    let root = cmdline_value(cmdline, "root").unwrap_or_default();
    if root != "/dev/dm-0" {
        return Err(format!(
            "the root ({}) is not the dm-verity device: booted by the fallback path",
            if root.is_empty() {
                "none"
            } else {
                root.as_str()
            }
        ));
    }
    let create = cmdline_value(cmdline, "dm-mod.create").ok_or("no dm-mod.create")?;
    // name,uuid,minor,flags,table — the table has no commas.
    let table = create
        .splitn(5, ',')
        .nth(4)
        .ok_or("dm-mod.create: no table")?;
    let w: Vec<&str> = table.split_ascii_whitespace().collect();
    let word = |i: usize| w.get(i).copied().unwrap_or("");
    if word(2) != "verity" {
        return Err(format!(
            "dm-mod.create: '{}' is not a verity table",
            word(2)
        ));
    }
    let num = |i: usize, what: &str| -> Result<u64, String> {
        word(i)
            .parse::<u64>()
            .map_err(|_| format!("dm-mod.create: bad {what}"))
    };
    let sectors = num(1, "length")?;
    let data_bs = num(6, "data block size")?;
    let data_blocks = num(8, "number of data blocks")?;
    if data_bs != verity::BLOCK as u64 {
        return Err(format!("dm-mod.create: data blocks of {data_bs} bytes"));
    }
    let bytes = data_blocks
        .checked_mul(data_bs)
        .filter(|b| *b > 0 && *b <= MAX_ROOT_BYTES)
        .ok_or("dm-mod.create: the root's size is out of range")?;
    if sectors.checked_mul(512) != Some(bytes) {
        return Err("dm-mod.create: the length and the data blocks disagree".into());
    }
    let root_hash = word(11);
    if root_hash.len() != 64 || !root_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("dm-mod.create: bad root hash".into());
    }
    Ok(VerityRoot {
        device: root,
        data_blocks,
        root_hash: root_hash.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "4d5b9c3f0e1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4";

    fn line(blocks: u64) -> String {
        let t = verity::table("PARTUUID=u-a", blocks, HASH, "00ff");
        format!(
            "BOOT_IMAGE=/x root=/dev/dm-0 dm-mod.waitfor=PARTUUID=u-a dm-mod.create=\"vroot,,,ro,{t}\" panic=10"
        )
    }

    #[test]
    fn the_root_size_comes_from_the_verity_table() {
        let r = verity_root(&line(22_272)).unwrap();
        assert_eq!(r.device, "/dev/dm-0");
        assert_eq!(r.data_blocks, 22_272);
        assert_eq!(r.bytes(), 22_272 * 4096);
        assert_eq!(r.root_hash, HASH);
        // GRUB hands the word over quoted whole (G1.6g).
        let g = line(16).replace("dm-mod.create=\"", "\"dm-mod.create=");
        assert_eq!(verity_root(&g).unwrap().data_blocks, 16);
    }

    #[test]
    fn a_root_without_verity_is_not_copied() {
        let e = verity_root("root=PARTUUID=3e1088b8 rootfstype=squashfs").unwrap_err();
        assert!(e.contains("fallback path"), "{e}");
        let e = verity_root("root=/dev/dm-0").unwrap_err();
        assert!(e.contains("no dm-mod.create"), "{e}");
        let bad = line(16).replace(" verity ", " linear ");
        assert!(
            verity_root(&bad)
                .unwrap_err()
                .contains("not a verity table")
        );
        // Hostile numbers: nothing overflows, nothing huge is asked for.
        let huge = line(16).replace(" 16 16 sha256", " 18446744073709551615 16 sha256");
        assert!(verity_root(&huge).unwrap_err().contains("out of range"));
        let odd = line(16).replace("0 128 verity", "0 64 verity");
        assert!(verity_root(&odd).unwrap_err().contains("disagree"));
        let short = line(16).replace(HASH, "abc");
        assert!(verity_root(&short).unwrap_err().contains("root hash"));
        assert!(verity_root("root=/dev/dm-0 dm-mod.create=\"vroot,,,ro,0 8\"").is_err());
    }

    #[test]
    fn ram_left_for_the_router() {
        let mem = |avail_mib: u64| {
            format!(
                "MemTotal: 1000000 kB\nMemFree: 1 kB\nMemAvailable: {} kB\n",
                avail_mib * 1024
            )
        };
        let root = 87 << 20;
        assert!(ram_check(&mem(400), root).is_ok());
        let e = ram_check(&mem(300), root).unwrap_err();
        assert!(
            e.contains("300 MiB of RAM available, 343 MiB needed"),
            "{e}"
        );
        assert!(ram_check("MemTotal: 1 kB\n", root).is_err());
    }

    #[test]
    fn options_and_states_survive_the_files() {
        let d = std::env::temp_dir().join(format!("cr-sysdisk-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        assert_eq!(load_options(&d).unwrap(), BootOptions::default());
        save_options(&d, BootOptions { to_ram: true }).unwrap();
        assert!(load_options(&d).unwrap().to_ram);
        assert!(options_path(&d).starts_with(d.join(crate::state::DIR)));
        fs::write(options_path(&d), "nonsense").unwrap();
        assert!(load_options(&d).is_err());
        // A newer field from a later image is ignored, not an error.
        fs::write(options_path(&d), r#"{"to_ram":true,"later":1}"#).unwrap();
        assert!(load_options(&d).unwrap().to_ram);

        assert_eq!(read_root(&d), None);
        let s = RootState {
            in_ram: true,
            bytes: 5,
            copy_ms: 7,
            disk: Some("sda".into()),
            note: None,
        };
        write_root(&d, &s).unwrap();
        assert_eq!(read_root(&d), Some(s));

        assert_eq!(read_gone(&d), None);
        write_gone(&d, &gone_line("sda", true)).unwrap();
        let g = read_gone(&d).unwrap();
        assert!(g.starts_with("system disk sda removed"), "{g}");
        assert!(g.contains("no longer saved"), "{g}");
        assert!(gone_line("vda", false).contains("may stop at any moment"));
        let _ = fs::remove_dir_all(&d);
    }
}

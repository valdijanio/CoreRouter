//! The live ISO (G1.6y, `docs/os-image.md`): what PID 1 does when the ISO's
//! kernel boots it (`corerouter.mode=live`, from the initramfs).
//!
//! The image's root is already on the medium, inside the signed update
//! package, so the live image adds nothing to the ISO but busybox. This
//! stage finds the medium, checks its signatures, copies the root to RAM,
//! checks it against the signed hash, mounts it and moves there. Then
//! `corerouter-init` runs again on that root as a router would, with
//! `/config` on a tmpfs, no FRR and no A/B state (`pid1`).
//!
//! When any of this fails (too little RAM, a bad medium), it stays on the
//! console installer, which needs none of it: the ISO always installs.
//! The hypervisor's unattended install (fw_cfg, the test's flag) goes there
//! too.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

use corerouter_sysupdate::install::Medium;
use corerouter_sysupdate::package;
use ring::digest::{Context, SHA256};
use rustix::mount::{MountFlags, UnmountFlags};

use crate::console::{self, Console};
use crate::pid1::{log, mount_api};
use crate::plan::{self, BootOptions};

const BUSYBOX: &str = "/bin/busybox";
/// The tmpfs holding the root's file; detached before the move (the loop
/// device keeps it alive).
const RAM_DIR: &str = "/live";
const RAM_FILE: &str = "/live/rootfs.img";
const NEW_ROOT: &str = "/newroot";
const CHUNK: usize = 1 << 20;

/// `/config` of the live image: nothing survives a reboot, and the disks it
/// sees are left alone.
pub fn mount_config() {
    let _ = std::fs::create_dir_all(plan::CONFIG_DIR);
    let flags = MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC | MountFlags::NOATIME;
    match rustix::mount::mount(
        "tmpfs",
        plan::CONFIG_DIR,
        "tmpfs",
        flags,
        c"mode=0700,size=64m",
    ) {
        Ok(()) => log("/config: tmpfs (live image: nothing here survives a reboot)"),
        Err(e) => log(&format!("/config: tmpfs: {e}")),
    }
}

/// Copies `size` bytes at `offset` of `from` to `to`, checking the SHA-256.
fn copy_checked(
    from: &mut impl Read,
    to: &mut impl Write,
    size: u64,
    want: &str,
) -> Result<(), String> {
    let mut ctx = Context::new(&SHA256);
    let mut buf = vec![0u8; CHUNK];
    let mut left = size;
    while left > 0 {
        let n = left.min(CHUNK as u64) as usize;
        let b = buf.get_mut(..n).ok_or("buffer")?;
        from.read_exact(b).map_err(|e| format!("medium: {e}"))?;
        ctx.update(b);
        to.write_all(b).map_err(|e| format!("RAM: {e}"))?;
        left -= n as u64;
    }
    let got = corerouter_sysupdate::verity::hex(ctx.finish().as_ref());
    if got != want {
        return Err("the root on the medium does not match its signed hash (bad medium?)".into());
    }
    Ok(())
}

/// The medium's root mounted at [`NEW_ROOT`], from RAM.
fn prepare(con: &Console) -> Result<String, String> {
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let total = plan::mem_total_kib(&meminfo).ok_or("no MemTotal in /proc/meminfo")?;
    if total < plan::LIVE_MIN_RAM_KIB {
        return Err(format!(
            "{} MiB of RAM; the live image needs 256 MiB",
            total / 1024
        ));
    }
    let keys = package::load_keys(Path::new(crate::install::KEYS));
    let (dev, mut medium): (String, Medium<File>) = crate::install::find_medium(con, &keys)?;
    let m = medium.header.manifest.clone();
    let e = medium.rootfs_extent()?;
    let size = format!("size={}k,mode=0700", e.size / 1024 + 1024);
    let size = std::ffi::CString::new(size).map_err(|e| e.to_string())?;
    let flags = MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC;
    rustix::mount::mount("tmpfs", RAM_DIR, "tmpfs", flags, size.as_c_str())
        .map_err(|e| format!("{RAM_DIR}: {e}"))?;
    medium
        .dev
        .seek(SeekFrom::Start(e.offset))
        .map_err(|e| e.to_string())?;
    let mut out = File::create(RAM_FILE).map_err(|e| format!("{RAM_FILE}: {e}"))?;
    copy_checked(&mut medium.dev, &mut out, e.size, &m.rootfs.sha256)?;
    drop(out);
    let st = Command::new(BUSYBOX)
        .args([
            "mount", "-t", "squashfs", "-o", "loop,ro", RAM_FILE, NEW_ROOT,
        ])
        .status()
        .map_err(|e| format!("{BUSYBOX}: {e}"))?;
    if !st.success() {
        return Err(format!("mounting the root from RAM: {st}"));
    }
    Ok(format!(
        "CoreRouter {} from {dev}, {} MiB in RAM, signed by key {}",
        m.version,
        e.size >> 20,
        medium.key
    ))
}

/// PID 1 on the ISO's initramfs: never returns.
pub fn enter(cmdline: &str) -> ! {
    let opts = BootOptions::parse(cmdline);
    if Path::new(crate::install::AUTOINSTALL).exists() {
        console_installer(&opts, cmdline);
    }
    let con = Console::open(&console::active(None));
    con.say("\nCoreRouter live: looking for the medium…");
    match prepare(&con) {
        Ok(line) => {
            log(&line);
            drop(con);
            move_to_root(&opts, cmdline)
        }
        Err(e) => {
            con.say(&format!(
                "The live image did not start: {e}\nThe console installer needs none of it."
            ));
            log(&format!("live image: {e}"));
            drop(con);
            console_installer(&opts, cmdline)
        }
    }
}

fn console_installer(opts: &BootOptions, cmdline: &str) -> ! {
    if Path::new("/sys/firmware/efi").exists() {
        mount_api(&plan::EFIVARS);
    }
    let _ = rustix::system::sethostname(b"corerouter-install");
    let _ = crate::pid1::name_ports(None);
    crate::install::run(opts, cmdline.trim())
}

fn move_to_root(opts: &BootOptions, cmdline: &str) -> ! {
    // The next stage mounts them again on the new root.
    for m in plan::MOUNTS.iter().rev() {
        let _ = rustix::mount::unmount(m.target, UnmountFlags::DETACH);
    }
    let _ = rustix::mount::unmount(RAM_DIR, UnmountFlags::DETACH);
    let e = Command::new(BUSYBOX)
        .args([
            "switch_root",
            NEW_ROOT,
            "/usr/sbin/corerouter-init",
            plan::LIVE_STAGE2,
        ])
        .exec();
    // Only when the exec failed. /dev is gone from under the console: put the
    // API filesystems back for the installer.
    for m in plan::MOUNTS {
        mount_api(m);
    }
    log(&format!("switch_root: {e}"));
    console_installer(opts, cmdline)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn hash(b: &[u8]) -> String {
        package::sha256_hex(b)
    }

    #[test]
    fn the_root_is_copied_only_when_it_matches_the_signed_hash() {
        let data = vec![7u8; 3 * CHUNK + 5];
        let mut out = Vec::new();
        copy_checked(
            &mut Cursor::new(&data),
            &mut out,
            data.len() as u64,
            &hash(&data),
        )
        .unwrap();
        assert_eq!(out, data);
        let e = copy_checked(
            &mut Cursor::new(&data),
            &mut Vec::new(),
            data.len() as u64,
            &hash(b"other"),
        )
        .unwrap_err();
        assert!(e.contains("signed hash"), "{e}");
    }

    #[test]
    fn a_short_medium_is_an_error_not_a_panic() {
        let e =
            copy_checked(&mut Cursor::new(vec![0u8; 10]), &mut Vec::new(), 20, "x").unwrap_err();
        assert!(e.contains("medium"), "{e}");
    }
}

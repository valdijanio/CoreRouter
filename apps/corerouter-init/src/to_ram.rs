//! G1.6zn: the installed system in RAM (`system.boot.set {to_ram: yes}`,
//! `corerouter_sysupdate::system_disk`).
//!
//! PID 1 starts on the slot's root, the squashfs on the dm-verity device
//! the boot entry describes (`root=/dev/dm-0`). With the option on, before
//! anything else runs:
//!
//! 1. the whole device is read into a tmpfs file. Reading it through
//!    dm-verity checks every block against the signed root hash of the
//!    command line, the check a boot from the disk does block by block: a
//!    block that fails is an I/O error here, and the boot stays on the disk;
//! 2. the file is mounted (loop, squashfs), made the root with
//!    `pivot_root(".", ".")` (the old root goes with a lazy unmount: the
//!    kernel's own threads move with it), and `corerouter-init` starts
//!    again from it with [`STAGE2`] (the live ISO's second stage, G1.6y,
//!    does the same from its initramfs with `switch_root`, which only works
//!    from an initramfs).
//!
//! `/config` was mounted to read the option: it is unmounted before the
//! move and the second stage mounts it again as any boot does.
//!
//! What can fail before the move (too little RAM, a block that fails the
//! check, no loop device) leaves the boot on the disk with one line that
//! says why; the router comes up either way.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::time::Instant;

use corerouter_sysupdate::system_disk::{self, RootState, VerityRoot};
use rustix::mount::{MountFlags, UnmountFlags};

use crate::pid1::log;
use crate::plan;

/// The argument the first stage passes to `corerouter-init` on the RAM
/// root, followed by the bytes copied and the milliseconds it took.
pub const STAGE2: &str = "--ram-root";
const BUSYBOX: &str = "/bin/busybox";
/// The tmpfs that holds the root's file: `/mnt`, an empty directory of the
/// image. Detached with the old root; the loop device keeps the file.
const RAM_DIR: &str = "/mnt";
const RAM_FILE: &str = "/mnt/rootfs.img";
const NEW_ROOT: &str = "/mnt/root";
const SELF: &str = "/usr/sbin/corerouter-init";
const CHUNK: usize = 1 << 20;

/// Where this boot's root comes from. `stage2`: the arguments after
/// [`STAGE2`], when this is the second stage. Returns only when the boot
/// goes on from the root it is on.
pub fn at_boot(cmdline: &str, config_dev: Option<&str>, stage2: Option<&[String]>) -> RootState {
    let disk = config_dev.and_then(crate::grow::disk_of).map(|d| d.0);
    if let Some(args) = stage2 {
        let num = |i: usize| args.get(i).and_then(|a| a.parse().ok()).unwrap_or(0);
        let (bytes, copy_ms) = (num(0), num(1));
        log(&format!(
            "system in RAM: {} MiB of root read from {} through dm-verity in {copy_ms} ms; the system disk can go",
            bytes >> 20,
            disk.as_deref().unwrap_or("the disk")
        ));
        return RootState {
            in_ram: true,
            bytes,
            copy_ms,
            disk,
            note: None,
        };
    }
    let on_disk = |note: Option<String>| RootState {
        in_ram: false,
        bytes: 0,
        copy_ms: 0,
        disk: disk.clone(),
        note,
    };
    // A /config on tmpfs (no partition) holds no option.
    if config_dev.is_none() {
        return on_disk(None);
    }
    let wanted = match system_disk::load_options(Path::new(plan::CONFIG_DIR)) {
        Ok(o) => o.to_ram,
        Err(e) => {
            log(&format!("boot options: {e}; the root stays on the disk"));
            false
        }
    };
    if !wanted {
        return on_disk(None);
    }
    match prepare(cmdline) {
        Ok((bytes, copy_ms)) => move_to_root(bytes, copy_ms),
        Err(e) => {
            let _ = rustix::mount::unmount(RAM_DIR, UnmountFlags::DETACH);
            log(&format!("system in RAM: {e}; running from the disk"));
            on_disk(Some(e))
        }
    }
}

/// The root in RAM, mounted at [`NEW_ROOT`]: (bytes, milliseconds of the
/// copy).
fn prepare(cmdline: &str) -> Result<(u64, u64), String> {
    let root = system_disk::verity_root(cmdline)?;
    let bytes = root.bytes();
    let meminfo = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    system_disk::ram_check(&meminfo, bytes)?;
    let size = format!("size={}k,mode=0700", bytes / 1024 + 1024);
    let size = std::ffi::CString::new(size).map_err(|e| e.to_string())?;
    let flags = MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC;
    rustix::mount::mount("tmpfs", RAM_DIR, "tmpfs", flags, size.as_c_str())
        .map_err(|e| format!("{RAM_DIR}: {e}"))?;
    let t = Instant::now();
    copy(&root)?;
    let ms = t.elapsed().as_millis() as u64;
    fs::create_dir(NEW_ROOT).map_err(|e| format!("{NEW_ROOT}: {e}"))?;
    let st = Command::new(BUSYBOX)
        .args([
            "mount", "-t", "squashfs", "-o", "loop,ro", RAM_FILE, NEW_ROOT,
        ])
        .status()
        .map_err(|e| format!("{BUSYBOX}: {e}"))?;
    if !st.success() {
        return Err(format!("mounting the root from RAM: {st}"));
    }
    if !Path::new(NEW_ROOT)
        .join(SELF.trim_start_matches('/'))
        .is_file()
    {
        let _ = rustix::mount::unmount(NEW_ROOT, UnmountFlags::DETACH);
        return Err(format!("the copy has no {SELF}"));
    }
    Ok((bytes, ms))
}

/// The verity device into [`RAM_FILE`]. Its pages leave the disk's cache
/// after: the root is in RAM once, not twice.
fn copy(root: &VerityRoot) -> Result<(), String> {
    let mut from = File::open(&root.device).map_err(|e| format!("{}: {e}", root.device))?;
    let mut to = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(RAM_FILE)
        .map_err(|e| format!("{RAM_FILE}: {e}"))?;
    let mut buf = vec![0u8; CHUNK];
    let mut left = root.bytes();
    while left > 0 {
        let n = left.min(CHUNK as u64) as usize;
        let b = buf.get_mut(..n).ok_or("buffer")?;
        // dm-verity answers a block that does not match its hash with EIO.
        from.read_exact(b).map_err(|e| {
            format!(
                "{} at {} MiB: {e} (a block that fails dm-verity, or a failing disk)",
                root.device,
                (root.bytes() - left) >> 20
            )
        })?;
        to.write_all(b).map_err(|e| format!("RAM: {e}"))?;
        left -= n as u64;
    }
    let _ = rustix::fs::fadvise(&from, 0, None, rustix::fs::Advice::DontNeed);
    Ok(())
}

/// Puts back what [`prepare`] mounted.
fn undo() {
    let _ = rustix::mount::unmount(NEW_ROOT, UnmountFlags::DETACH);
    let _ = rustix::mount::unmount(RAM_DIR, UnmountFlags::DETACH);
}

/// From the disk's root to the RAM's, and `corerouter-init` again there.
/// Returns (on the disk) only when the move could not be made.
fn move_to_root(bytes: u64, copy_ms: u64) -> RootState {
    rustix::fs::sync();
    // The second stage mounts it again (and may grow it: nothing may hold it).
    if let Err(e) = rustix::mount::unmount(plan::CONFIG_DIR, UnmountFlags::empty()) {
        undo();
        let note = format!("/config: unmount: {e}");
        log(&format!("system in RAM: {note}; running from the disk"));
        return RootState {
            in_ram: false,
            bytes: 0,
            copy_ms: 0,
            disk: None,
            note: Some(note),
        };
    }
    let pivoted =
        rustix::process::chdir(NEW_ROOT).and_then(|()| rustix::process::pivot_root(".", "."));
    if let Err(e) = pivoted {
        let _ = rustix::process::chdir("/");
        undo();
        let note = format!("pivot_root: {e}");
        log(&format!("system in RAM: {note}; running from the disk"));
        remount_config();
        return RootState {
            in_ram: false,
            bytes: 0,
            copy_ms: 0,
            disk: None,
            note: Some(note),
        };
    }
    // The old root sits on top of the new one at "."; it goes with its
    // mounts (/proc, /dev, /run, the tmpfs of the file…).
    if let Err(e) = rustix::mount::unmount(".", UnmountFlags::DETACH) {
        log(&format!("system in RAM: the old root stays mounted: {e}"));
    }
    let _ = rustix::process::chdir("/");
    let e = Command::new(SELF)
        .args([STAGE2, &bytes.to_string(), &copy_ms.to_string()])
        .exec();
    // Only when the exec failed: the API filesystems went with the old root.
    for m in plan::MOUNTS {
        crate::pid1::mount_api(m);
    }
    log(&format!(
        "system in RAM: {SELF}: {e}; going on from RAM with the old init"
    ));
    remount_config();
    RootState {
        in_ram: true,
        bytes,
        copy_ms,
        disk: None,
        note: Some(format!("exec: {e}")),
    }
}

fn remount_config() {
    let Some(name) = crate::pid1::find_partition(plan::CONFIG_PARTLABEL) else {
        return;
    };
    let dev = format!("/dev/{name}");
    let fl = MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC | MountFlags::NOATIME;
    if let Err(e) = rustix::mount::mount(
        dev.as_str(),
        plan::CONFIG_DIR,
        "ext4",
        fl,
        c"errors=remount-ro",
    ) {
        log(&format!("/config: mount {dev}: {e}"));
    }
}

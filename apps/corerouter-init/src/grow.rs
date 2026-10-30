//! G1.6v: `/config` takes the rest of the disk. The image's `/config` is
//! 64 MiB (the layout of `disk.img`); the installer writes the partition to
//! the end of the target disk, and a router installed before this grows it
//! here, in two boots:
//!
//! 1. after `/config` is mounted, outside a trial boot (one that may roll
//!    back): the partition table ([`gpt::grow_last`], only the `config`
//!    entry changes). The kernel keeps the old size until the next boot;
//! 2. at the next boot, before `/config` is mounted: the filesystem grows
//!    to its partition (`e2fsck -f -p`, `resize2fs`; [`ext4::grow`]).
//!
//! A disk that would leave `/config` under [`gpt::CONFIG_MIN`] keeps its
//! layout, and the boot log says so. Each step returns what to log.

use std::fs::{self, File, OpenOptions};
use std::path::Path;

use corerouter_sysupdate::{ext4, gpt};

const MIB: u64 = 1 << 20;
/// Where e2fsprogs is on the image (Buildroot's `/sbin`), then elsewhere.
const TOOLS: [&str; 2] = ["/sbin", "/usr/sbin"];

/// A number in a sysfs file (`size` is in 512-byte sectors whatever the
/// disk's block size).
fn sys_u64(path: &str) -> Option<u64> {
    fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Step 2: the filesystem on `dev` (`/dev/vda4`) grows to its partition
/// when the partition is bigger by a MiB or more.
pub(crate) fn filesystem(dev: &str) -> Vec<String> {
    let name = dev.trim_start_matches("/dev/");
    let Some(part) = sys_u64(&format!("/sys/class/block/{name}/size")).map(|s| s * 512) else {
        return Vec::new();
    };
    let fs = match File::open(dev)
        .map_err(|e| e.to_string())
        .and_then(|mut f| ext4::fs_bytes(&mut f))
    {
        Ok(b) => b,
        Err(e) => return vec![format!("/config: {dev}: {e}")],
    };
    if !ext4::needs_grow(part, fs) {
        return Vec::new();
    }
    let dirs: Vec<&Path> = TOOLS.iter().map(Path::new).collect();
    let Some((e2fsck, resize2fs)) = ext4::tools(&dirs) else {
        return vec![format!(
            "/config: the partition has {} MiB and the filesystem {} MiB, but this image has no resize2fs",
            part / MIB,
            fs / MIB
        )];
    };
    let mut log = vec![format!(
        "/config: growing the filesystem from {} to {} MiB",
        fs / MIB,
        part / MIB
    )];
    match ext4::grow(Path::new(dev), &e2fsck, &resize2fs) {
        Ok(lines) => log.extend(lines.into_iter().map(|l| format!("/config: {l}"))),
        Err(e) => log.push(format!("/config: {e}; mounted as it is")),
    }
    log
}

/// Step 1: the `config` partition of the disk holding `dev` reaches the
/// end of the disk. Not during a trial boot: the table changes once the
/// update is confirmed (the next normal boot).
pub(crate) fn table(dev: &str, trial: bool) -> Vec<String> {
    if trial {
        return Vec::new();
    }
    let name = dev.trim_start_matches("/dev/");
    // /sys/class/block/vda4 → …/block/vda/vda4: the disk is the parent.
    let Some(disk) = fs::read_link(format!("/sys/class/block/{name}"))
        .ok()
        .and_then(|l| Some(l.parent()?.file_name()?.to_str()?.to_owned()))
    else {
        return Vec::new();
    };
    let (Some(sectors), Some(lbs)) = (
        sys_u64(&format!("/sys/block/{disk}/size")),
        sys_u64(&format!("/sys/block/{disk}/queue/logical_block_size")),
    ) else {
        return Vec::new();
    };
    let f = match OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!("/dev/{disk}"))
    {
        Ok(f) => f,
        Err(e) => return vec![format!("/config: /dev/{disk}: {e}")],
    };
    match gpt::grow_last(&f, sectors * 512, lbs, "config", gpt::CONFIG_MIN) {
        Ok(gpt::Grow::Grow { from, to }) => vec![format!(
            "/config: partition grown from {} to {} MiB (the rest of /dev/{disk}); the filesystem follows at the next boot",
            from / MIB,
            to / MIB
        )],
        Ok(gpt::Grow::TooSmall { could, min }) => vec![format!(
            "/config: /dev/{disk} leaves room for {} MiB, under the minimum of {} MiB: the layout stays (a bigger disk grows it)",
            could / MIB,
            min / MIB
        )],
        Ok(gpt::Grow::Full { .. }) => Vec::new(),
        Err(e) => vec![format!("/config: partition table of /dev/{disk}: {e}")],
    }
}

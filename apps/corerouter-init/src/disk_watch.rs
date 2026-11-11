//! G1.6zn: the system disk going away with the router running (a USB stick
//! pulled out, a USB SSD that resets and comes back under another name).
//!
//! Before this the console filled with the kernel's `SQUASHFS error`,
//! `EXT4-fs (sda4) … I/O error` and `FAT-fs (sda1) … bread failed`, one
//! for every read of the root, every commit of `/config`'s journal and
//! every look at the ESP, and nothing said what had happened. Now a thread
//! sleeps on the kernel's device messages (no polling; it wakes on each
//! uevent, rare on a router) and, when a disk that holds the system leaves:
//!
//! 1. the console shows only emergencies from then on (`console_loglevel`
//!    1): the errors still go to the kernel's log, and the OS log reader
//!    takes them to the router's log, but they no longer bury the line;
//! 2. `/config` and the ESP are unmounted (lazily: an open file keeps its
//!    filesystem), so nothing more is asked of the missing disk;
//! 3. one line (`system_disk::gone_line`) goes to the console and the
//!    router's log, and to `<runtime>/system-disk-removed`: the daemon's
//!    config storage refuses changes with it, and the package service
//!    reports it to the health check.
//!
//! The root in RAM (`to_ram`) keeps the router running; from the disk, it
//! runs only as long as what it reads is in the page cache, and the line
//! says so.

use std::fs;
use std::path::Path;
use std::time::Duration;

use corerouter_sysupdate::system_disk;
use rustix::mount::UnmountFlags;

use crate::pid1::log;
use crate::plan;

/// The disks the system is on: the one holding `/config` and the ones
/// under the root's dm-verity device.
pub fn system_disks(config_dev: Option<&str>) -> Vec<String> {
    let mut parts: Vec<String> = config_dev.map(str::to_owned).into_iter().collect();
    if let Ok(slaves) = fs::read_dir("/sys/block/dm-0/slaves") {
        for e in slaves.flatten() {
            if let Some(n) = e.file_name().to_str() {
                parts.push(format!("/dev/{n}"));
            }
        }
    }
    let mut disks: Vec<String> = Vec::new();
    for p in parts {
        if let Some((d, _, _)) = crate::grow::disk_of(&p)
            && !disks.contains(&d)
        {
            disks.push(d);
        }
    }
    disks
}

/// The first of `disks` that is gone.
fn gone(disks: &[String], exists: impl Fn(&str) -> bool) -> Option<&str> {
    disks.iter().map(String::as_str).find(|d| !exists(d))
}

fn present(disk: &str) -> bool {
    Path::new("/sys/class/block").join(disk).exists()
}

/// Starts the watch over `disks` (nothing to watch: nothing started).
pub fn spawn(disks: Vec<String>, in_ram: bool) {
    if disks.is_empty() {
        return;
    }
    let events = match open_uevents() {
        Ok(s) => Some(s),
        Err(e) => {
            log(&format!(
                "system disk: no device messages ({e}); looking every second instead"
            ));
            None
        }
    };
    let spawned = std::thread::Builder::new()
        .name("disk-watch".into())
        .spawn(move || {
            let mut buf = vec![0u8; 16 << 10];
            loop {
                if let Some(disk) = gone(&disks, present) {
                    removed(disk, in_ram);
                    return;
                }
                match &events {
                    Some(s) => {
                        // ENOBUFS (messages lost) also means "look again".
                        if let Err(e) = s.recv(&mut &mut buf[..], 0)
                            && e.raw_os_error() != Some(105)
                        {
                            std::thread::sleep(Duration::from_secs(1));
                        }
                    }
                    None => std::thread::sleep(Duration::from_secs(1)),
                }
            }
        });
    if let Err(e) = spawned {
        log(&format!("system disk: watch thread: {e}"));
    }
}

fn open_uevents() -> std::io::Result<netlink_sys::Socket> {
    use netlink_sys::{Socket, SocketAddr as NlAddr, protocols::NETLINK_KOBJECT_UEVENT};
    // Group 1: the kernel's own messages (udev's are group 2).
    let mut sock = Socket::new(NETLINK_KOBJECT_UEVENT)?;
    sock.bind(&NlAddr::new(0, 1))?;
    Ok(sock)
}

/// What a system disk that went away gets (once).
fn removed(disk: &str, in_ram: bool) {
    let line = system_disk::gone_line(disk, in_ram);
    // Only KERN_EMERG on the console from now on: ext4_error() prints at
    // KERN_CRIT and squashfs at KERN_ERR, above `quiet`'s level 4.
    if let Err(e) = fs::write("/proc/sys/kernel/printk", "1") {
        log(&format!("console log level: {e}"));
    }
    if let Err(e) = system_disk::write_gone(Path::new(plan::RUNTIME_DIR), &line) {
        log(&format!("system disk: {e}"));
    }
    for m in [plan::CONFIG_DIR, corerouter_sysupdate::ab::ESP_MOUNT] {
        let _ = rustix::mount::unmount(m, UnmountFlags::DETACH);
    }
    log(&line);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_missing_disk_is_named() {
        let disks = vec!["sda".to_owned(), "sdb".to_owned()];
        assert_eq!(gone(&disks, |_| true), None);
        assert_eq!(gone(&disks, |d| d != "sdb"), Some("sdb"));
        assert_eq!(gone(&[], |_| false), None);
    }
}

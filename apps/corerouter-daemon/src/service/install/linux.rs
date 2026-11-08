//! The Linux side of the `install` service (G1.6y).

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use corerouter_engine::install::{self, Holds, Job, MediumInfo};
use corerouter_engine::{Shared, lock};
use corerouter_sysupdate::disks::{self, BUTTON_PRESSES, CHALLENGE_OPEN, KEYS};
use corerouter_sysupdate::install::{self as writer, Existing, Medium};
use corerouter_sysupdate::package;
use serde_json::json;

use super::super::{Ctx, Health, IDLE_BEAT, Run};

const TICK: Duration = Duration::from_millis(200);
/// How often to look for the medium while it is not there.
const MEDIUM_RETRY: Duration = Duration::from_secs(2);
/// Presses of the power button that stand for the code, and in how long.
const PRESSES: usize = 3;
const PRESS_WINDOW: Duration = Duration::from_secs(30);
const EFIVARS: &str = "/sys/firmware/efi/efivars";

type TheMedium = Option<(String, Medium<File>)>;

pub(super) fn start(ctx: &Ctx) -> Result<Run, String> {
    let session: Shared = ctx.session.clone();
    let live = ctx.flag("--live").is_some();
    if live {
        let mut s = lock(&session);
        corerouter_engine::live::set(&mut s);
        let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
        let mounts = std::fs::read_to_string("/proc/mounts").unwrap_or_default();
        install::set_support(
            &mut s,
            match installed_evidence(&cmdline, &mounts) {
                Some(why) => Err(why),
                None => Ok(()),
            },
        );
        drop(s);
        log::warn!("live image: not installed; only the network test and the install can change anything");
    }
    Ok(Box::new(move |health: &Health| {
        if !live {
            health.disabled(Some("this router is installed"));
            health.beat();
            while health.sleep(IDLE_BEAT) {
                health.beat();
            }
            return Ok(());
        }
        let mut state = State::new();
        health.beat();
        while health.sleep(TICK) {
            health.beat();
            state.tick(&session);
        }
        Ok(())
    }))
}

/// The second lock (`--live` is the first): what says this system is
/// installed, whatever the flag claims.
fn installed_evidence(cmdline: &str, mounts: &str) -> Option<String> {
    if !cmdline.split_whitespace().any(|w| w == "corerouter.mode=live") {
        return Some("the kernel was not booted live: this system is installed".into());
    }
    let config = mounts.lines().find_map(|l| {
        let mut f = l.split_whitespace();
        let (dev, at, fs) = (f.next()?, f.next()?, f.next()?);
        (at == "/config").then(|| (dev.to_owned(), fs.to_owned()))
    });
    match config {
        Some((dev, fs)) if fs != "tmpfs" => {
            Some(format!("/config is {dev} ({fs}): this system is installed"))
        }
        _ => None,
    }
}

struct State {
    medium: TheMedium,
    worker: Option<JoinHandle<TheMedium>>,
    next_find: Instant,
    /// `/sys/block` as last read: a change rescans (a stick plugged in).
    seen: String,
    deadline: Option<Instant>,
    presses_seen: u64,
    press_times: Vec<Instant>,
}

impl State {
    fn new() -> Self {
        State {
            medium: None,
            worker: None,
            next_find: Instant::now(),
            seen: String::new(),
            deadline: None,
            presses_seen: 0,
            press_times: Vec::new(),
        }
    }

    fn tick(&mut self, session: &Shared) {
        self.challenge(session);
        if let Some(w) = self.worker.take_if(|w| w.is_finished()) {
            self.medium = w.join().unwrap_or_else(|_| {
                log::error!("install: the worker thread panicked");
                None
            });
        }
        if self.worker.is_some() {
            return;
        }
        let job = install::take_job(&mut lock(session));
        let seen = block_signature();
        let rescan = install::take_rescan(&mut lock(session)) || seen != self.seen;
        let medium = self.medium.take();
        let session = session.clone();
        let work: Box<dyn FnOnce() -> TheMedium + Send> = match (job, medium) {
            (Some(job), Some(m)) => Box::new(move || {
                let mut m = m;
                let r = write(&session, &mut m, &job);
                if let Err(e) = &r {
                    log::error!("install: {e}");
                }
                install::finish(&mut lock(&session), r);
                Some(m)
            }),
            (Some(_), None) => {
                install::finish(&mut lock(&session), Err("the installer medium is gone".into()));
                return;
            }
            (None, None) if Instant::now() >= self.next_find || rescan => {
                self.next_find = Instant::now() + MEDIUM_RETRY;
                self.seen = seen;
                Box::new(move || {
                    let keys = package::load_keys(Path::new(KEYS));
                    let found = disks::find_medium(&keys, &mut |name, e| {
                        log::warn!("install: {name}: an installer medium, but unusable: {e}");
                    });
                    publish(&session, found.as_ref());
                    found
                })
            }
            (None, Some(m)) if rescan => {
                self.seen = seen;
                Box::new(move || {
                    let found = Some(m);
                    publish(&session, found.as_ref());
                    found
                })
            }
            (None, medium) => {
                self.medium = medium;
                return;
            }
        };
        match std::thread::Builder::new().name("install-work".into()).spawn(work) {
            Ok(h) => self.worker = Some(h),
            Err(e) => log::error!("install: cannot start the worker: {e}"),
        }
    }

    fn challenge(&mut self, session: &Shared) {
        let announce = install::take_announcement(&mut lock(session));
        if let Some(c) = announce {
            self.deadline = Some(Instant::now() + Duration::from_secs(u64::from(install::CHALLENGE_SECS)));
            self.press_times.clear();
            self.presses_seen = presses();
            let _ = std::fs::create_dir_all("/run/corerouter");
            if let Err(e) = std::fs::write(CHALLENGE_OPEN, b"") {
                log::warn!("{CHALLENGE_OPEN}: {e}");
            }
            let (detail, what) = {
                let s = lock(session);
                let d = s.ext::<install::Install>().and_then(|i| i.disks.iter().find(|d| d.name == c.disk).cloned());
                (d.as_ref().map(|d| d.detail.clone()).unwrap_or_default(), d.map(|d| format!("{} {} serial {}", d.bus, disks::human(d.bytes), d.serial)).unwrap_or_default())
            };
            log::warn!("install: {} asks to erase {} ({what}; holds {detail})", c.by, c.disk);
            console(&[
                String::new(),
                format!("*** {} asks to ERASE {} ({what}), which holds: {detail}", c.by, c.disk),
                format!("*** Code: {}   ({} minutes, {} tries). Not you? Do nothing.", c.code, install::CHALLENGE_SECS / 60, install::CHALLENGE_ATTEMPTS),
                format!("*** No console at hand? Press the power button {PRESSES} times within {} s.", PRESS_WINDOW.as_secs()),
                String::new(),
            ]);
        }
        let open = lock(session).ext::<install::Install>().is_some_and(|i| i.challenge.is_some());
        let Some(deadline) = self.deadline else {
            return;
        };
        if !open {
            self.deadline = None;
            let _ = std::fs::remove_file(CHALLENGE_OPEN);
            return;
        }
        let left = deadline.saturating_duration_since(Instant::now()).as_secs();
        install::set_remaining(&mut lock(session), left.max(u64::from(deadline > Instant::now())) as u32);
        let count = presses();
        for _ in self.presses_seen..count {
            self.press_times.push(Instant::now());
        }
        self.presses_seen = count;
        self.press_times.retain(|t| t.elapsed() <= PRESS_WINDOW);
        if self.press_times.len() >= PRESSES {
            self.press_times.clear();
            install::set_presence(&mut lock(session));
            log::warn!("install: power button pressed {PRESSES} times: confirmed");
            console(&["*** Power button: confirmed. The install can go on.".to_owned()]);
        }
    }
}

fn presses() -> u64 {
    std::fs::metadata(BUTTON_PRESSES).map_or(0, |m| m.len())
}

/// Names and sizes of the disks: cheap, read every tick.
fn block_signature() -> String {
    disks::block_devices(true)
        .iter()
        .map(|n| format!("{n}={} ", disks::sys(&format!("/sys/block/{n}/size"))))
        .collect()
}

/// To the consoles the kernel uses, whatever is on them. Never blocks on a
/// stopped serial line.
fn console(lines: &[String]) {
    let active = disks::sys("/sys/class/tty/console/active");
    let text: String = lines.iter().map(|l| format!("\r{l}\r\n")).collect();
    for name in active.split_whitespace() {
        let flags = rustix::fs::OFlags::NONBLOCK | rustix::fs::OFlags::NOCTTY;
        let opened = OpenOptions::new()
            .write(true)
            .custom_flags(flags.bits() as i32)
            .open(format!("/dev/{name}"));
        if let Err(e) = opened.and_then(|mut f| f.write_all(text.as_bytes())) {
            log::warn!("install: console {name}: {e}");
        }
    }
}

fn holds(e: &Existing) -> Holds {
    match e {
        Existing::Empty => Holds::Empty,
        Existing::CoreRouter { .. } => Holds::CoreRouter,
        Existing::Gpt(_) | Existing::Unknown => Holds::Data,
    }
}

/// Reads the disks and shows them.
fn publish(session: &Shared, medium: Option<&(String, Medium<File>)>) {
    let Some((dev, m)) = medium else {
        let mut s = lock(session);
        install::set_scan(&mut s, None, Vec::new());
        return;
    };
    let ds = disks::list(dev, &m.index, disks::booted_by_bios());
    let listed = ds
        .iter()
        .map(|d| install::Disk {
            name: d.name.clone(),
            bytes: d.bytes,
            model: d.model.clone(),
            serial: d.serial.clone(),
            bus: d.bus.to_owned(),
            removable: d.removable,
            holds: holds(&d.existing),
            detail: disks::describe(&d.existing),
            config_keepable: d.existing == (Existing::CoreRouter { config_keepable: true }),
            refused: d.refused.clone(),
        })
        .collect();
    let man = &m.header.manifest;
    let info = MediumInfo {
        device: dev.clone(),
        version: man.version.clone(),
        commit: man.commit.clone(),
        channel: man.channel.clone(),
        signed_by: m.key.clone(),
        min_disk: m.index.min_disk(),
    };
    install::set_scan(&mut lock(session), Some(info), listed);
}

/// Looks at the disk once more and writes. The confirmation was for what the
/// list showed; a disk swapped or filled since then starts over.
fn write(session: &Shared, medium: &mut (String, Medium<File>), job: &Job) -> Result<serde_json::Value, String> {
    let (dev, m) = medium;
    let fresh = disks::list(dev, &m.index, disks::booted_by_bios());
    let d = fresh
        .iter()
        .find(|d| d.name == job.disk)
        .ok_or_else(|| format!("{} is gone", job.disk))?;
    if d.serial != job.serial || d.bytes != job.bytes {
        return Err(format!("{} is not the disk that was confirmed: serial or size changed", d.name));
    }
    if let Some(r) = &d.refused {
        return Err(format!("{} cannot be the target: {r}", d.name));
    }
    let now = holds(&d.existing);
    if now != job.holds {
        return Err(format!(
            "{} changed since it was confirmed: it held {}, it holds {}. Nothing was written; look at the list again",
            d.name,
            job.holds.as_str(),
            now.as_str()
        ));
    }
    log::warn!("install: {} installs on {} ({})", job.by, d.name, disks::describe(&d.existing));
    // O_EXCL on a block device: refused while anything (a mount, a holder)
    // uses it.
    let target = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(rustix::fs::OFlags::EXCL.bits() as i32)
        .open(format!("/dev/{}", d.name))
        .map_err(|e| {
            if e.raw_os_error() == Some(16) {
                format!("{} is in use (mounted, RAID or LVM): stop that and try again", d.name)
            } else {
                format!("/dev/{}: {e}", d.name)
            }
        })?;
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let mut shown = 0;
    let bios = disks::booted_by_bios();
    let manifest = m.header.manifest.clone();
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let rootfs_a = m.index.part("rootfs-a").map(|p| p.guid.clone()).unwrap_or_default();
    let line = writer::slot_a_line(&rootfs_a, &manifest, cmdline.trim(), &[]);
    let report = writer::install(
        m,
        &target,
        d.bytes,
        d.lbs,
        &writer::Opts {
            keep_config: job.keep_config,
            pipelined: true,
            parallel_verify: true,
            threads,
            bios_active: bios,
            bios_cmdline: Some(line.clone()),
        },
        &mut |done, total| {
            let pct = done * 100 / total.max(1);
            if pct != shown {
                shown = pct;
                let phase = if done == total { "verifying" } else { "writing" };
                install::set_progress(&mut lock(session), phase, done, total);
            }
        },
    )?;
    drop(target);
    // G1.6g: on a BIOS the disk already boots through GRUB, with this line.
    let boot = if bios {
        Ok(format!("BIOS boot: GRUB in the first blocks of {}, slot A", d.name))
    } else {
        writer::boot_entry(EFIVARS, &report, &line)
    };
    if let Err(e) = &boot {
        log::warn!("install: boot entry: {e}");
    }
    log::warn!("install: CoreRouter {} on {} in {} ms", manifest.version, d.name, report.total_ms);
    Ok(json!({
        "disk": d.name,
        "version": manifest.version,
        "bytes_written": report.bytes_written,
        "write_ms": report.write_ms,
        "verify_ms": report.verify_ms,
        "total_ms": report.total_ms,
        "kept_config": report.kept_config,
        "boot_entry": boot.as_ref().ok(),
        "boot_entry_error": boot.as_ref().err(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn what_says_this_system_is_installed() {
        let live = "console=ttyS0 corerouter.mode=live panic=10";
        let tmp = "/dev/root / squashfs ro 0 0\ntmpfs /config tmpfs rw 0 0\n";
        assert_eq!(installed_evidence(live, tmp), None);
        assert_eq!(installed_evidence(live, "/dev/root / squashfs ro 0 0\n"), None);
        assert!(installed_evidence("root=/dev/dm-0", tmp).unwrap().contains("not booted live"));
        let e = installed_evidence(live, "/dev/vda4 /config ext4 rw 0 0\n").unwrap();
        assert!(e.contains("/dev/vda4"), "{e}");
    }

    #[test]
    fn only_a_blank_disk_counts_as_empty() {
        assert_eq!(holds(&Existing::Empty), Holds::Empty);
        assert_eq!(holds(&Existing::Unknown), Holds::Data);
        assert_eq!(holds(&Existing::Gpt(vec![])), Holds::Data);
        assert_eq!(holds(&Existing::CoreRouter { config_keepable: false }), Holds::CoreRouter);
    }
}

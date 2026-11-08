//! System › Install to disk (G1.6y): `--live` tells the daemon it runs from
//! the ISO, not installed (`corerouter_engine::live`). This service reads the
//! disks and writes the image for `system.install.*`.
//!
//! The body only ticks: reads and writes run on one worker thread at a time,
//! outside the session lock, so `print` answers and the health beats while a
//! spinning disk takes minutes. One install per machine: nothing to divide
//! here, and `corerouter_sysupdate::install` already reads, hashes and writes
//! on separate threads. The network test checks each port on its own thread:
//! a dead gateway costs its timeout once, not once per port.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{IpAddr, UdpSocket};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::process::Command;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use corerouter_control::tls;
use corerouter_engine::install::{self, Holds, Job, MediumInfo, TestRequest};
use corerouter_engine::{Shared, lock};
use corerouter_sysupdate::disks::{self, BUTTON_PRESSES, CHALLENGE_OPEN, KEYS};
use corerouter_sysupdate::install::{self as writer, Existing, Medium};
use corerouter_sysupdate::package;
use serde_json::json;

pub(crate) const SERVICE: super::Service = super::Service {
    name: "install",
    flags: &[super::Flag {
        name: "--live",
        value: None,
        help: "The image runs live from the installer ISO, not installed (corerouter-init passes it)",
    }],
    topic: "system",
    enable: "always on in the live image (System › Install to disk)",
    depends: &[],
    start,
};

const TICK: Duration = Duration::from_millis(200);
/// How often to look for the medium while it is not there.
const MEDIUM_RETRY: Duration = Duration::from_secs(2);
/// Presses of the power button that stand for the code, and in how long.
const PRESSES: usize = 3;
const PRESS_WINDOW: Duration = Duration::from_secs(30);
const EFIVARS: &str = "/sys/firmware/efi/efivars";
const LIVE_CONFIG: &str = "/config";
const NEW_CONFIG: &str = "/run/corerouter/new-config";
const BUSYBOX: &str = "/bin/busybox";
/// A DNS answer can take a while right after boot (G1.6qc).
const DNS_TRIES: u32 = 3;
const DNS_WAIT: Duration = Duration::from_secs(1);
const ARP_TRIES: u32 = 4;
const ARP_WAIT: Duration = Duration::from_millis(300);

/// Enough for the ring of a 256 MiB machine.
const KMSG_MAX: usize = 100_000;

type TheMedium = Option<(String, Medium<File>)>;

fn start(ctx: &super::Ctx) -> Result<super::Run, String> {
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
    Ok(Box::new(move |health: &super::Health| {
        if !live {
            health.disabled(Some("this router is installed"));
            health.beat();
            while health.sleep(super::IDLE_BEAT) {
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
        if let Some(req) = install::take_test(&mut lock(session)) {
            let medium = self.medium.take();
            let session = session.clone();
            self.spawn(Box::new(move || {
                let v = network_test(&session, &req);
                install::set_network(&mut lock(&session), v);
                medium
            }));
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
        self.spawn(work);
    }

    fn spawn(&mut self, work: Box<dyn FnOnce() -> TheMedium + Send>) {
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
    let ds = disks::list(dev, &m.index);
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
    let fresh = disks::list(dev, &m.index);
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
    let manifest = m.header.manifest.clone();
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let boot = writer::boot_entry(EFIVARS, &report, &manifest, cmdline.trim(), &[]);
    if let Err(e) = &boot {
        log::warn!("install: boot entry: {e}");
    }
    // The disk is written and read back; what follows only helps the first
    // boot, so a failure is reported and is not a failed install.
    let first_boot = if job.keep_config {
        Ok(())
    } else {
        let hash = lock(session).password_hash("admin");
        let at = m.index.part("config").map(|p| p.offset).ok_or("no config partition");
        at.map_err(str::to_owned).and_then(|at| first_boot_data(&d.name, at, job, hash.as_deref()))
    };
    if let Err(e) = &first_boot {
        log::warn!("install: first-boot data: {e}");
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
        "mgmt_port": job.mgmt.as_ref().map(|m| m.port.clone()),
        "first_boot_error": first_boot.as_ref().err(),
    }))
}

/// The new `/config`, by loop at its offset: the kernel has not re-read the
/// partition table, and this needs no `ioctl`. The same certificate (the GUI
/// that trusted the live image trusts the router), the port names, and what
/// PID 1 applies on the first boot. A separate `losetup`: busybox 1.37
/// `mount` takes `offset=` only for a regular file and hands it to the kernel
/// for a block device, which says EINVAL (`util-linux/mount.c:2114`).
fn first_boot_data(disk: &str, offset: u64, job: &Job, admin_hash: Option<&str>) -> Result<(), String> {
    std::fs::create_dir_all(NEW_CONFIG).map_err(|e| format!("{NEW_CONFIG}: {e}"))?;
    let lo = busybox(&["losetup", "-f"])?;
    let lo = lo.trim();
    busybox(&["losetup", "-o", &offset.to_string(), lo, &format!("/dev/{disk}")])?;
    let mounted = busybox(&["mount", "-t", "ext4", lo, NEW_CONFIG]);
    let wrote = mounted.and_then(|_| {
        let wrote = write_first_boot(job, admin_hash);
        wrote.and(busybox(&["umount", NEW_CONFIG]).map(drop))
    });
    wrote.and(busybox(&["losetup", "-d", lo]).map(drop))
}

fn write_first_boot(job: &Job, admin_hash: Option<&str>) -> Result<(), String> {
    let new = Path::new(NEW_CONFIG);
    let live = Path::new(LIVE_CONFIG);
    for name in [tls::CERT_FILE, tls::KEY_FILE, ".port-names"] {
        match std::fs::read(live.join(name)) {
            Ok(data) => durable(&new.join(name), &data, name == tls::KEY_FILE)?,
            Err(e) => log::warn!("install: {name}: {e}"),
        }
    }
    let data = first_boot_json(job, admin_hash);
    durable(&new.join(disks::FIRST_BOOT), data.to_string().as_bytes(), true)?;
    File::open(new).and_then(|d| d.sync_all()).map_err(|e| format!("{NEW_CONFIG}: {e}"))
}

fn first_boot_json(job: &Job, admin_hash: Option<&str>) -> serde_json::Value {
    json!({
        "mgmt": job.mgmt.as_ref().map(|m| json!({
            "port": m.port, "address": m.address, "gateway": m.gateway, "dns": m.dns,
        })),
        "admin_password_hash": admin_hash,
    })
}

fn durable(path: &Path, data: &[u8], private: bool) -> Result<(), String> {
    let mut o = OpenOptions::new();
    o.write(true).create(true).truncate(true).mode(if private { 0o600 } else { 0o644 });
    let write = o.open(path).and_then(|mut f| {
        f.write_all(data)?;
        f.sync_all()
    });
    write.map_err(|e| format!("{}: {e}", path.display()))
}

fn busybox(args: &[&str]) -> Result<String, String> {
    let out = Command::new(BUSYBOX)
        .args(args)
        .output()
        .map_err(|e| format!("{BUSYBOX}: {e}"))?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    Err(format!(
        "{}: {}",
        args.first().unwrap_or(&""),
        err.trim().chars().take(200).collect::<String>()
    ))
}

/// A port, as the operator needs it before erasing a disk.
fn network_test(session: &Shared, req: &TestRequest) -> serde_json::Value {
    let (addresses, clients) = {
        let mut s = lock(session);
        (
            s.execute("ip.address.list", &json!({})).unwrap_or_default(),
            s.execute("ip.dhcp-client.list", &json!({})).unwrap_or_default(),
        )
    };
    let empty = Vec::new();
    let addresses = addresses.as_array().unwrap_or(&empty);
    let clients = clients.as_array().unwrap_or(&empty);
    let (mut by_device, other_firmware) = firmware_by_device(&read_kmsg());
    let ports = physical_ports();
    let local = req.local.map(|l| l.to_string());
    let connected = local.as_deref().and_then(|l| {
        addresses.iter().find_map(|a| {
            let at = a["address"].as_str()?.split('/').next()?;
            (at == l).then(|| a["interface"].as_str().map(str::to_owned))?
        })
    });
    // Every port at once: a dead gateway or DNS costs its timeouts once, not
    // once per port.
    let checks: Vec<(Option<bool>, Option<bool>)> = std::thread::scope(|scope| {
        let handles: Vec<_> = ports
            .iter()
            .map(|p| {
                let client = clients.iter().find(|c| c["interface"] == p.name.as_str());
                let gateway = client.and_then(|c| c["gateway"].as_str()).filter(|g| !g.is_empty()).map(str::to_owned);
                let dns = client.map(dns_of).unwrap_or_default();
                let (name, up) = (p.name.clone(), p.link);
                scope.spawn(move || {
                    let gw = gateway.filter(|_| up).map(|g| gateway_answers(&g, &name));
                    let d = (up && !dns.is_empty()).then(|| dns.iter().any(|d| dns_answers(d)));
                    (gw, d)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap_or((None, None))).collect()
    });
    let mut problems = Vec::new();
    let mut out = Vec::new();
    for (p, (gateway_ok, dns_ok)) in ports.iter().zip(checks) {
        let client = clients.iter().find(|c| c["interface"] == p.name.as_str());
        let address = addresses.iter().find(|a| a["interface"] == p.name.as_str()).and_then(|a| a["address"].as_str());
        let firmware = by_device.remove(&p.device).unwrap_or_default();
        if !firmware.is_empty() {
            // G1.6j: the kernel of the ISO has no firmware files; the installed
            // image does. A note about now, not a defect of the card.
            problems.push(format!("{}: firmware not on the live image ({}): the port may work in a reduced mode until installed", p.name, firmware.join(", ")));
        }
        if p.link && address.is_none() {
            problems.push(format!("{}: link, but no address yet", p.name));
        }
        if gateway_ok == Some(false) {
            problems.push(format!("{}: the gateway does not answer", p.name));
        }
        if dns_ok == Some(false) {
            problems.push(format!("{}: no DNS server answers", p.name));
        }
        out.push(json!({
            "name": p.name,
            "mac": p.mac,
            "driver": p.driver,
            "link": p.link,
            "speed_mbps": p.speed,
            "address": address,
            "dhcp_status": client.and_then(|c| c["status"].as_str()),
            "gateway": client.and_then(|c| c["gateway"].as_str()).filter(|g| !g.is_empty()),
            "gateway_ok": gateway_ok,
            "dns": client.map(dns_of).unwrap_or_default(),
            "dns_ok": dns_ok,
            "firmware": firmware,
            "connected": connected.as_deref() == Some(p.name.as_str()),
        }));
    }
    // A port without a cable is normal; no port with one is not.
    if !ports.iter().any(|p| p.link) {
        problems.push("no port has a link".to_owned());
    }
    // What the kernel asked for and no port owns (`regulatory.db` of Wi-Fi):
    // for the curious, not a problem.
    let mut leftover: Vec<String> = by_device.into_values().flatten().chain(other_firmware).collect();
    leftover.sort();
    leftover.dedup();
    json!({"connected_port": connected, "ports": out, "problems": problems, "firmware": leftover})
}

fn dns_of(client: &serde_json::Value) -> Vec<String> {
    ["primary_dns", "secondary_dns"]
        .iter()
        .filter_map(|k| client[*k].as_str())
        .filter(|d| !d.is_empty())
        .map(str::to_owned)
        .collect()
}

struct Port {
    name: String,
    mac: String,
    driver: String,
    /// The device's bus address, as the kernel's messages name it.
    device: String,
    link: bool,
    speed: Option<u32>,
}

/// Ports with a device behind them; no driver, no port here at all.
fn physical_ports() -> Vec<Port> {
    let mut out: Vec<Port> = std::fs::read_dir("/sys/class/net")
        .map(|d| {
            d.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter_map(|name| {
                    let base = format!("/sys/class/net/{name}");
                    let device = std::fs::canonicalize(format!("{base}/device")).ok()?;
                    let tail = |p: &Path| p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                    let driver = std::fs::canonicalize(format!("{base}/device/driver")).map(|p| tail(&p)).unwrap_or_default();
                    Some(Port {
                        mac: disks::sys(&format!("{base}/address")),
                        driver,
                        device: tail(&device),
                        link: disks::sys(&format!("{base}/carrier")) == "1",
                        // -1 when the driver does not know (virtio, no link).
                        speed: disks::sys(&format!("{base}/speed")).parse::<u32>().ok(),
                        name,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// A datagram makes the kernel resolve the gateway; an answered ARP is what
/// proves the path. Nothing needs raw sockets, and the datagram goes nowhere
/// (the discard port).
fn gateway_answers(gateway: &str, port: &str) -> bool {
    let Ok(ip) = gateway.parse::<IpAddr>() else {
        return false;
    };
    let Ok(sock) = UdpSocket::bind(if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }) else {
        return false;
    };
    for _ in 0..ARP_TRIES {
        let _ = sock.send_to(b"", (ip, 9));
        std::thread::sleep(ARP_WAIT);
        let arp = std::fs::read_to_string("/proc/net/arp").unwrap_or_default();
        if arp_answered(&arp, gateway, port) {
            return true;
        }
    }
    false
}

fn arp_answered(table: &str, ip: &str, port: &str) -> bool {
    table.lines().skip(1).any(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        matches!(f.as_slice(), [a, _, flags, _, _, dev] if *a == ip && *dev == port && *flags != "0x0")
    })
}

/// The root's NS, the smallest question there is. Any answer with our id will
/// do: an error still proves the server is there.
fn dns_query(id: [u8; 2]) -> [u8; 17] {
    let [a, b] = id;
    [a, b, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1]
}

fn dns_reply_ok(reply: &[u8], id: [u8; 2]) -> bool {
    matches!(reply, [a, b, flags, ..] if [*a, *b] == id && flags & 0x80 != 0)
}

fn dns_answers(server: &str) -> bool {
    let Ok(ip) = server.parse::<IpAddr>() else {
        return false;
    };
    let Ok(sock) = UdpSocket::bind(if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" }) else {
        return false;
    };
    if sock.set_read_timeout(Some(DNS_WAIT)).is_err() || sock.connect((ip, 53)).is_err() {
        return false;
    }
    let mut id = [0u8; 2];
    let _ = getrandom::fill(&mut id);
    let mut buf = [0u8; 512];
    (0..DNS_TRIES).any(|_| {
        let _ = sock.send(&dns_query(id));
        sock.recv(&mut buf)
            .is_ok_and(|n| dns_reply_ok(buf.get(..n).unwrap_or(&[]), id))
    })
}

/// The kernel's messages so far, without waiting for new ones.
fn read_kmsg() -> Vec<String> {
    let flags = rustix::fs::OFlags::NONBLOCK;
    let Ok(mut f) = OpenOptions::new()
        .read(true)
        .custom_flags(flags.bits() as i32)
        .open("/dev/kmsg")
    else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    // One record per read; EPIPE when the ring wrapped under us: go on.
    for _ in 0..KMSG_MAX {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let rec = String::from_utf8_lossy(buf.get(..n).unwrap_or(&[]));
                if let Some((_, text)) = rec.split_once(';') {
                    out.push(text.trim_end().to_owned());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) if e.raw_os_error() == Some(32) => {}
            Err(_) => break,
        }
    }
    out
}

/// The firmware file a kernel line says is missing, and the device it names.
/// Not one text: `request_firmware` says "Direct firmware load", `r8169` asks
/// without a warning and logs its own, `e100` and `ice` theirs (G1.6j read
/// them in the kernel's source).
fn missing_firmware(line: &str) -> Option<(Option<String>, String)> {
    let between = |from: &str, to: &str| -> Option<String> {
        let (_, rest) = line.split_once(from)?;
        let (file, _) = rest.split_once(to)?;
        Some(file.to_owned())
    };
    let file = between("Direct firmware load for ", " failed")
        .or_else(|| between("Unable to load firmware ", " ("))
        .or_else(|| between("Needs \"", "\""))
        .or_else(|| line.contains("DDP package file was not found").then(|| "intel/ice/ddp/ice.pkg".to_owned()))?;
    // "r8169 0000:02:00.0: Unable to …": driver, device, text.
    let device = line
        .split_once(": ")
        .and_then(|(head, _)| head.split_whitespace().nth(1))
        .map(str::to_owned);
    Some((device, file))
}

fn firmware_by_device(lines: &[String]) -> (BTreeMap<String, Vec<String>>, Vec<String>) {
    let mut by = BTreeMap::<String, Vec<String>>::new();
    let mut other = Vec::new();
    for (device, file) in lines.iter().filter_map(|l| missing_firmware(l)) {
        match device {
            Some(d) => {
                let files = by.entry(d).or_default();
                if !files.contains(&file) {
                    files.push(file);
                }
            }
            None => other.push(file),
        }
    }
    (by, other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_lines_of_every_kind() {
        for (line, device, file) in [
            ("r8169 0000:02:00.0: Unable to load firmware rtl_nic/rtl8168h-2.fw (-2)", Some("0000:02:00.0"), "rtl_nic/rtl8168h-2.fw"),
            ("e100 0000:01:01.0: CPUSaver disabled. Needs \"e100/d101m_ucode.bin\": -2", Some("0000:01:01.0"), "e100/d101m_ucode.bin"),
            ("ice 0000:03:00.0: The DDP package file was not found or could not be read", Some("0000:03:00.0"), "intel/ice/ddp/ice.pkg"),
            ("tg3 0000:04:00.0: Direct firmware load for tigon/tg3_tso5.bin failed with error -2", Some("0000:04:00.0"), "tigon/tg3_tso5.bin"),
        ] {
            let (d, f) = missing_firmware(line).unwrap();
            assert_eq!((d.as_deref(), f.as_str()), (device, file), "{line}");
        }
        assert_eq!(missing_firmware("r8169 0000:02:00.0: eth0: link up"), None);
        let (by, other) = firmware_by_device(&[
            "r8169 0000:02:00.0: Unable to load firmware a.fw (-2)".into(),
            "r8169 0000:02:00.0: Unable to load firmware a.fw (-2)".into(),
        ]);
        assert_eq!(by.get("0000:02:00.0").unwrap(), &["a.fw"]);
        assert!(other.is_empty());
    }

    #[test]
    fn an_answered_arp_is_what_counts() {
        let t = "IP address       HW type     Flags       HW address            Mask     Device\n\
                 10.0.2.2         0x1         0x2         52:55:0a:00:02:02     *        ether1\n\
                 10.0.3.2         0x1         0x0         00:00:00:00:00:00     *        ether2\n";
        assert!(arp_answered(t, "10.0.2.2", "ether1"));
        assert!(!arp_answered(t, "10.0.2.2", "ether2"), "another port");
        assert!(!arp_answered(t, "10.0.3.2", "ether2"), "incomplete");
    }

    #[test]
    fn dns_question_and_answer() {
        let q = dns_query([0xab, 0xcd]);
        assert_eq!(q.get(..3), Some(&[0xab, 0xcd, 1][..]));
        assert!(dns_reply_ok(&[0xab, 0xcd, 0x81, 0x83], [0xab, 0xcd]), "an error answer proves the server");
        assert!(!dns_reply_ok(&[0xab, 0xcd, 0x01], [0xab, 0xcd]), "not an answer");
        assert!(!dns_reply_ok(&[0xab, 0xce, 0x81], [0xab, 0xcd]), "another id");
        assert!(!dns_reply_ok(&[], [0xab, 0xcd]));
    }

    #[test]
    fn the_first_boot_gets_the_choice_and_the_hash() {
        let job = Job {
            disk: "vda".into(),
            serial: "S".into(),
            bytes: 1,
            holds: Holds::Empty,
            keep_config: false,
            mgmt: Some(install::Mgmt {
                port: "ether1".into(),
                address: None,
                gateway: None,
                dns: vec![],
            }),
            by: "t".into(),
        };
        let v = first_boot_json(&job, Some("$argon2id$x"));
        assert_eq!(v["mgmt"]["port"], "ether1");
        assert!(v["mgmt"]["address"].is_null());
        assert_eq!(v["admin_password_hash"], "$argon2id$x");
    }

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

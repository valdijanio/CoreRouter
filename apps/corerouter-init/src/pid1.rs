//! The syscalls behind `plan`: everything here runs as PID 1, where a panic
//! or an early return is a kernel panic, so every failure is logged and the
//! boot goes on with whatever still works.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rustix::mount::{MountFlags, UnmountFlags};
use rustix::process::{Pid, Signal, WaitOptions};
use rustix::system::RebootCommand;

use corerouter_sysupdate::SlotId;
use corerouter_sysupdate::ab::{self, Boot};
use corerouter_sysupdate::efi::Vars;

use crate::plan::{self, Backoff, BootOptions};

/// One line on the console (the kernel gives PID 1 `/dev/console` as fds
/// 0–2). Never panics, unlike `eprintln!`.
fn log(msg: &str) {
    let _ = writeln!(std::io::stderr(), "corerouter-init: {msg}");
}

macro_rules! log {
    ($($a:tt)*) => { log(&format!($($a)*)) };
}

/// The main loop's tick: reaping, restarts, the readiness probe and the
/// signal flags are all checked this often (cost: one `waitpid` and a few
/// atomics per tick).
const TICK: Duration = Duration::from_millis(50);
/// The daemon gets this long to save state after SIGTERM.
const STOP_GRACE: Duration = Duration::from_secs(10);
/// How long to wait for the `config` partition to show up (async probing).
const CONFIG_WAIT: Duration = Duration::from_secs(5);
/// The daemon's stdout/stderr (tmpfs); copied to `.1` and truncated past
/// this size, so a chatty daemon never fills `/var` nor blocks on a 115200
/// baud console.
const DAEMON_LOG: &str = "/var/log/corerouter-daemon.log";
const DAEMON_LOG_MAX: u64 = 8 << 20;
/// Idle memory is read this long after the first ready.
const IDLE_AFTER: Duration = Duration::from_secs(10);

// What a signal asks for (stored by the handler, acted on by the loop).
const RUN: usize = 0;
const REBOOT: usize = 1;
const POWEROFF: usize = 2;
const HALT: usize = 3;

pub fn main() {
    let started = Instant::now();
    if rustix::process::getpid() != Pid::INIT {
        log("not PID 1: refusing to run (this is the image's init)");
        std::process::exit(2);
    }
    for m in plan::MOUNTS {
        mount_api(m);
    }
    let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let opts = BootOptions::parse(&cmdline);
    for w in &opts.warnings {
        log!("kernel command line: {w}");
    }
    // Ctrl-Alt-Del becomes SIGINT to us (a clean reboot), not an instant one.
    let _ = rustix::system::reboot(RebootCommand::CadOff);
    if let Err(e) = rustix::system::sethostname(b"corerouter") {
        log!("hostname: {e}");
    }
    if let Err(e) = loopback_up() {
        log!("lo up: {e} (the control channel listens on 127.0.0.1)");
    }
    mount_config();
    let trial = trial_at_boot(&cmdline);
    for dir in [plan::RUNTIME_DIR, "/var/log", "/var/lib", "/var/tmp"] {
        if let Err(e) = fs::create_dir_all(dir) {
            log!("{dir}: {e}");
        }
    }
    let action = Arc::new(AtomicUsize::new(RUN));
    for (sig, what) in [
        (signal_hook::consts::SIGTERM, REBOOT),
        (signal_hook::consts::SIGINT, REBOOT),
        (signal_hook::consts::SIGUSR2, POWEROFF),
        (signal_hook::consts::SIGUSR1, HALT),
    ] {
        if let Err(e) = signal_hook::flag::register_usize(sig, Arc::clone(&action), what) {
            log!("signal {sig}: {e}");
        }
    }
    log!("early boot done in {} ms", started.elapsed().as_millis());
    supervise(&opts, &action, started, trial);
}

/// A trial boot of the A/B image (G1.6b) being watched: reboot into the
/// previous slot unless the daemon confirms it before `deadline`.
struct TrialWatch {
    slot: SlotId,
    from: SlotId,
    timeout_s: u64,
    deadline: Instant,
    vars: Vars,
    next_check: Instant,
}

/// efivarfs, then the boot step of the A/B image: marks a trial booted or
/// records the failed one (restoring the configuration it ran with) before
/// the daemon reads `/config`.
fn trial_at_boot(cmdline: &str) -> Option<TrialWatch> {
    if !std::path::Path::new("/sys/firmware/efi").exists() {
        return None;
    }
    mount_api(&plan::EFIVARS);
    let vars = Vars::efivarfs(plan::EFIVARS.target);
    let (boot, lines) = ab::at_boot(
        std::path::Path::new(plan::CONFIG_DIR),
        &vars,
        cmdline,
        ab::fallback_partuuids(),
    );
    for l in &lines {
        log!("{l}");
    }
    match boot {
        Boot::Normal => None,
        Boot::Trial {
            slot,
            from,
            timeout_s,
        } => Some(TrialWatch {
            slot,
            from,
            timeout_s,
            deadline: Instant::now() + Duration::from_secs(timeout_s),
            vars,
            next_check: Instant::now(),
        }),
    }
}

fn flags(m: &plan::Mount) -> MountFlags {
    let mut f = MountFlags::empty();
    if m.nosuid {
        f |= MountFlags::NOSUID;
    }
    if m.nodev {
        f |= MountFlags::NODEV;
    }
    if m.noexec {
        f |= MountFlags::NOEXEC;
    }
    f
}

fn mount_api(m: &plan::Mount) {
    let _ = fs::create_dir_all(m.target);
    let data = std::ffi::CString::new(m.data).unwrap_or_default();
    match rustix::mount::mount(m.source, m.target, m.fstype, flags(m), data.as_c_str()) {
        // devtmpfs is already there with CONFIG_DEVTMPFS_MOUNT.
        Ok(()) | Err(rustix::io::Errno::BUSY) => {}
        Err(e) => log!("mount {} on {}: {e}", m.fstype, m.target),
    }
}

/// `/config` from the `config` partition; tmpfs (and a loud warning) when
/// it is missing or does not mount, so the router still comes up and can be
/// reached to fix it.
fn mount_config() {
    let _ = fs::create_dir_all(plan::CONFIG_DIR);
    let deadline = Instant::now() + CONFIG_WAIT;
    let dev = loop {
        if let Some(name) = find_partition(plan::CONFIG_PARTLABEL) {
            break Some(format!("/dev/{name}"));
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(TICK);
    };
    let fl = MountFlags::NOSUID | MountFlags::NODEV | MountFlags::NOEXEC | MountFlags::NOATIME;
    if let Some(dev) = dev {
        match rustix::mount::mount(
            dev.as_str(),
            plan::CONFIG_DIR,
            "ext4",
            fl,
            c"errors=remount-ro",
        ) {
            Ok(()) => {
                log!("/config: {dev} (ext4)");
                return;
            }
            Err(e) => log!("/config: mount {dev}: {e}"),
        }
    } else {
        log!("/config: no partition named '{}'", plan::CONFIG_PARTLABEL);
    }
    log("/config: using tmpfs — CONFIGURATION WILL NOT SURVIVE A REBOOT");
    if let Err(e) = rustix::mount::mount(
        "tmpfs",
        plan::CONFIG_DIR,
        "tmpfs",
        fl,
        c"mode=0700,size=64m",
    ) {
        log!("/config: tmpfs: {e}");
    }
}

fn find_partition(label: &str) -> Option<String> {
    let entries = fs::read_dir("/sys/class/block").ok()?;
    let devs: Vec<(String, String)> = entries
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            let uevent = fs::read_to_string(e.path().join("uevent")).ok()?;
            Some((name, uevent))
        })
        .collect();
    plan::partition_by_label(devs.iter().map(|(n, u)| (n.as_str(), u.as_str())), label)
        .map(str::to_owned)
}

/// `ip link set lo up` as one RTM_NEWLINK (ifindex 1 is always `lo` in the
/// initial namespace), so the image needs no `ip` binary for it.
fn loopback_up() -> std::io::Result<()> {
    use netlink_sys::{Socket, SocketAddr as NlAddr, protocols::NETLINK_ROUTE};
    const RTM_NEWLINK: u16 = 16;
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_ACK: u16 = 4;
    const NLMSG_ERROR: u16 = 2;
    const IFF_UP: u32 = 1;
    let mut msg = Vec::with_capacity(32);
    msg.extend_from_slice(&32u32.to_ne_bytes()); // nlmsg_len
    msg.extend_from_slice(&RTM_NEWLINK.to_ne_bytes());
    msg.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    msg.extend_from_slice(&1u32.to_ne_bytes()); // seq
    msg.extend_from_slice(&0u32.to_ne_bytes()); // pid
    msg.extend_from_slice(&[0, 0]); // ifi_family, pad
    msg.extend_from_slice(&0u16.to_ne_bytes()); // ifi_type
    msg.extend_from_slice(&1i32.to_ne_bytes()); // ifi_index
    msg.extend_from_slice(&IFF_UP.to_ne_bytes()); // ifi_flags
    msg.extend_from_slice(&IFF_UP.to_ne_bytes()); // ifi_change
    let mut sock = Socket::new(NETLINK_ROUTE)?;
    sock.bind_auto()?;
    sock.send_to(&msg, &NlAddr::new(0, 0), 0)?;
    let (reply, _) = sock.recv_from_full()?;
    let u16_at = |i: usize| {
        reply
            .get(i..i + 2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_ne_bytes)
    };
    let i32_at = |i: usize| {
        reply
            .get(i..i + 4)
            .and_then(|b| b.try_into().ok())
            .map(i32::from_ne_bytes)
    };
    match (u16_at(4), i32_at(16)) {
        (Some(NLMSG_ERROR), Some(0)) => Ok(()),
        (Some(NLMSG_ERROR), Some(e)) => Err(std::io::Error::from_raw_os_error(-e)),
        _ => Err(std::io::Error::other("unexpected netlink reply")),
    }
}

struct Daemon {
    pid: Option<Pid>,
    since: Instant,
    restart_at: Instant,
    backoff: Backoff,
    ready: bool,
}

fn supervise(
    opts: &BootOptions,
    action: &AtomicUsize,
    boot: Instant,
    mut trial: Option<TrialWatch>,
) -> ! {
    let mut d = Daemon {
        pid: None,
        since: Instant::now(),
        restart_at: Instant::now(),
        backoff: Backoff::new(),
        ready: false,
    };
    let mut shell: Option<Pid> = None;
    let mut shell_at = Instant::now();
    let mut idle_at: Option<Instant> = None;
    let mut idle_done = false;
    let mut next_rotate = Instant::now();
    loop {
        let what = action.load(Ordering::Relaxed);
        if what != RUN {
            shutdown(what, d.pid, shell);
        }
        // Reap every child that exited: ours and orphans reparented to PID 1.
        while let Ok(Some((pid, status))) = rustix::process::waitpid(None, WaitOptions::NOHANG) {
            if Some(pid) == d.pid {
                let ran = d.since.elapsed();
                let delay = d.backoff.after_exit(ran);
                log!(
                    "corerouter-daemon exited ({status:?}) after {:.1} s; restart in {:.1} s",
                    ran.as_secs_f64(),
                    delay.as_secs_f64()
                );
                tail_log(20);
                d.pid = None;
                d.ready = false;
                d.restart_at = Instant::now() + delay;
            } else if Some(pid) == shell {
                shell = None;
                shell_at = Instant::now() + Duration::from_secs(1);
            }
        }
        let now = Instant::now();
        if d.pid.is_none() && now >= d.restart_at {
            d.pid = spawn_daemon(opts);
            d.since = now;
            if d.pid.is_none() {
                d.restart_at = now + d.backoff.after_exit(Duration::ZERO);
            }
        }
        if d.pid.is_some() && !d.ready && probe() {
            d.ready = true;
            let up = read_proc("/proc/uptime").and_then(|s| plan::uptime_secs(&s));
            log!(
                "ready: control channel answered ping, {:.3} s after kernel start (init +{:.3} s, daemon start +{:.3} s)",
                up.unwrap_or(-1.0),
                boot.elapsed().as_secs_f64(),
                d.since.elapsed().as_secs_f64()
            );
            if !idle_done {
                idle_at.get_or_insert(now + IDLE_AFTER);
            }
        }
        if idle_at.is_some_and(|t| now >= t) {
            idle_at = None;
            idle_done = true;
            let used = read_proc("/proc/meminfo").and_then(|s| plan::mem_used_kib(&s));
            log!(
                "idle: memory in use {} KiB (MemTotal − MemAvailable)",
                used.unwrap_or(0)
            );
        }
        if let Some(tty) = &opts.shell
            && shell.is_none()
            && now >= shell_at
        {
            shell = spawn_shell(tty);
            shell_at = now + Duration::from_secs(5);
        }
        if let Some(t) = &mut trial
            && now >= t.next_check
        {
            t.next_check = now + Duration::from_secs(1);
            if ab::primary(&t.vars) == Some(t.slot) {
                log!("trial boot of slot {} confirmed", t.slot.as_str());
                trial = None;
            } else if now >= t.deadline {
                log!(
                    "trial boot of slot {} not confirmed in {} s: rebooting into slot {}",
                    t.slot.as_str(),
                    t.timeout_s,
                    t.from.as_str()
                );
                shutdown(REBOOT, d.pid, shell);
            }
        }
        if now >= next_rotate {
            rotate_log();
            next_rotate = now + Duration::from_secs(5);
        }
        std::thread::sleep(TICK);
    }
}

fn read_proc(path: &str) -> Option<String> {
    fs::read_to_string(path).ok()
}

fn spawn_daemon(opts: &BootOptions) -> Option<Pid> {
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(DAEMON_LOG);
    let (out, err) = match log_file.and_then(|f| Ok((f.try_clone()?, f))) {
        Ok((a, b)) => (Stdio::from(a), Stdio::from(b)),
        Err(e) => {
            log!("{DAEMON_LOG}: {e}; daemon output goes to the console");
            (Stdio::inherit(), Stdio::inherit())
        }
    };
    let spawned = Command::new(plan::DAEMON)
        .args(plan::daemon_args(opts))
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", plan::CONFIG_DIR)
        .env("COREROUTER_RUNTIME_DIR", plan::RUNTIME_DIR)
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(out)
        .stderr(err)
        .spawn();
    match spawned {
        Ok(child) => {
            log!("started corerouter-daemon (pid {})", child.id());
            // The loop reaps it with waitpid(-1); the Child is not waited on.
            i32::try_from(child.id()).ok().and_then(Pid::from_raw)
        }
        Err(e) => {
            log!("{}: {e}", plan::DAEMON);
            None
        }
    }
}

/// The maintenance shell: busybox `sh` with `tty` as its controlling
/// terminal (`setsid -c`). Only with `corerouter.shell=<tty>`.
fn spawn_shell(tty: &str) -> Option<Pid> {
    let path = format!("/dev/{tty}");
    let open = || OpenOptions::new().read(true).write(true).open(&path);
    let (Ok(i), Ok(o), Ok(e)) = (open(), open(), open()) else {
        log!("maintenance shell: cannot open {path}");
        return None;
    };
    let spawned = Command::new("/usr/bin/setsid")
        .args(["-c", "/bin/sh", "-l"])
        .env_clear()
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .env("HOME", "/tmp")
        .env("TERM", "linux")
        .env("COREROUTER_RUNTIME_DIR", plan::RUNTIME_DIR)
        .stdin(i)
        .stdout(o)
        .stderr(e)
        .spawn();
    match spawned {
        Ok(c) => {
            log!("maintenance shell on {path}");
            i32::try_from(c.id()).ok().and_then(Pid::from_raw)
        }
        Err(e) => {
            log!("maintenance shell: {e}");
            None
        }
    }
}

/// Does the daemon answer `ping` on the loopback control channel?
fn probe() -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], plan::CONTROL_PORT));
    let Ok(mut s) = TcpStream::connect_timeout(&addr, Duration::from_millis(200)) else {
        return false;
    };
    let _ = s.set_read_timeout(Some(Duration::from_millis(500)));
    let _ = s.set_write_timeout(Some(Duration::from_millis(500)));
    if s.write_all(b"{\"id\":1,\"method\":\"ping\"}\n").is_err() {
        return false;
    }
    let mut line = String::new();
    let _ = BufReader::new(s.take(4096)).read_line(&mut line);
    plan::is_pong(&line)
}

/// The last `n` lines of the daemon's log on the console (why it died).
fn tail_log(n: usize) {
    let Ok(mut f) = File::open(DAEMON_LOG) else {
        return;
    };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let _ = f.seek(SeekFrom::Start(len.saturating_sub(16 << 10)));
    let mut buf = Vec::new();
    let _ = f.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    let lines: Vec<&str> = text.lines().collect();
    for l in lines.iter().skip(lines.len().saturating_sub(n)) {
        log!("  daemon: {l}");
    }
}

/// Copy-truncate: the daemon keeps its `O_APPEND` descriptor and goes on
/// writing at the new end.
fn rotate_log() {
    let Ok(meta) = fs::metadata(DAEMON_LOG) else {
        return;
    };
    if meta.len() <= DAEMON_LOG_MAX {
        return;
    }
    let _ = fs::copy(DAEMON_LOG, format!("{DAEMON_LOG}.1"));
    if let Ok(f) = OpenOptions::new().write(true).open(DAEMON_LOG) {
        let _ = f.set_len(0);
    }
}

fn shutdown(what: usize, daemon: Option<Pid>, shell: Option<Pid>) -> ! {
    let name = match what {
        POWEROFF => "power off",
        HALT => "halt",
        _ => "reboot",
    };
    log!("{name}: stopping services");
    if let Some(p) = shell {
        let _ = rustix::process::kill_process(p, Signal::HUP);
    }
    if let Some(p) = daemon {
        let _ = rustix::process::kill_process(p, Signal::TERM);
        let deadline = Instant::now() + STOP_GRACE;
        loop {
            match rustix::process::waitpid(Some(p), WaitOptions::NOHANG) {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) if Instant::now() >= deadline => {
                    log!(
                        "corerouter-daemon did not stop in {} s: killing it",
                        STOP_GRACE.as_secs()
                    );
                    let _ = rustix::process::kill_process(p, Signal::KILL);
                    let _ = rustix::process::waitpid(Some(p), WaitOptions::empty());
                    break;
                }
                Ok(None) => std::thread::sleep(TICK),
            }
        }
    }
    rustix::fs::sync();
    if let Err(e) = rustix::mount::unmount(plan::CONFIG_DIR, UnmountFlags::empty()) {
        log!("/config: unmount: {e}; remounting read-only");
        let _ = rustix::mount::mount_remount(plan::CONFIG_DIR, MountFlags::RDONLY, "");
    }
    rustix::fs::sync();
    let cmd = match what {
        POWEROFF => RebootCommand::PowerOff,
        HALT => RebootCommand::Halt,
        _ => RebootCommand::Restart,
    };
    let e = rustix::system::reboot(cmd);
    log!("{name}: {e:?}; halting here");
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

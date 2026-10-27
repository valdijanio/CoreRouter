//! What PID 1 decides, kept apart from the syscalls so it is tested on any
//! host: boot options from `/proc/cmdline`, the mount table, the daemon's
//! command line, the restart backoff and the readings for the boot report.

use std::time::Duration;

/// Where the daemon lives in the image and how it is started.
pub const DAEMON: &str = "/usr/bin/corerouter-daemon";
/// Plain control channel, loopback only (the daemon refuses anything else).
pub const CONTROL_PORT: u16 = 7979;
/// TLS control channel for the network (login required).
pub const TLS_LISTEN: &str = "0.0.0.0:8729";
/// Writable, persistent configuration (the `config` GPT partition).
pub const CONFIG_DIR: &str = "/config";
/// GPT partition name (PARTLABEL) of the configuration partition.
pub const CONFIG_PARTLABEL: &str = "config";
/// Runtime files (control token); tmpfs.
pub const RUNTIME_DIR: &str = "/run/corerouter";

/// A filesystem mounted before anything else runs.
pub struct Mount {
    pub source: &'static str,
    pub target: &'static str,
    pub fstype: &'static str,
    pub data: &'static str,
    /// Mount flags as names, turned into `MountFlags` by the caller.
    pub nosuid: bool,
    pub nodev: bool,
    pub noexec: bool,
}

const fn m(
    source: &'static str,
    target: &'static str,
    fstype: &'static str,
    data: &'static str,
    noexec: bool,
) -> Mount {
    Mount {
        source,
        target,
        fstype,
        data,
        nosuid: true,
        nodev: true,
        noexec,
    }
}

/// Order matters: `/dev` before `/dev/pts`, `/sys` before what lives in it.
/// The root (squashfs) stays read-only; everything that must be written is
/// tmpfs except `/config`.
pub const MOUNTS: &[Mount] = &[
    m("proc", "/proc", "proc", "", true),
    m("sysfs", "/sys", "sysfs", "", true),
    Mount {
        nodev: false,
        ..m("devtmpfs", "/dev", "devtmpfs", "mode=0755", true)
    },
    m(
        "devpts",
        "/dev/pts",
        "devpts",
        "gid=5,mode=0620,ptmxmode=0666",
        true,
    ),
    m("tmpfs", "/dev/shm", "tmpfs", "mode=1777", true),
    m("tmpfs", "/run", "tmpfs", "mode=0755,size=64m", true),
    m("tmpfs", "/tmp", "tmpfs", "mode=1777,size=256m", true),
    m("tmpfs", "/var", "tmpfs", "mode=0755,size=256m", true),
    m("cgroup2", "/sys/fs/cgroup", "cgroup2", "nsdelegate", true),
    // XDP maps and programs pinned by hal-linux (G2.5).
    m("bpf", "/sys/fs/bpf", "bpf", "mode=0700", true),
    m("tracefs", "/sys/kernel/tracing", "tracefs", "", true),
];

/// Options read from the kernel command line (`corerouter.<key>=<value>`).
/// Unknown keys are ignored (the command line belongs to the kernel too);
/// bad values fall back to the default and are reported.
#[derive(Debug, PartialEq, Eq)]
pub struct BootOptions {
    /// Maintenance shell on this terminal (`corerouter.shell=ttyS0`). Off by
    /// default: the router is managed through its control channel, like a
    /// RouterOS box (no shell at all) or Talos (API only).
    pub shell: Option<String>,
    /// `linux` (the default: the router drives this kernel) or `virtual`.
    pub backend: String,
    /// Complaints about the command line, logged once at boot.
    pub warnings: Vec<String>,
}

const MAX_TTY: usize = 16;

impl BootOptions {
    pub fn parse(cmdline: &str) -> Self {
        let mut out = BootOptions {
            shell: None,
            backend: "linux".into(),
            warnings: Vec::new(),
        };
        for word in cmdline.split_ascii_whitespace() {
            let Some(rest) = word.strip_prefix("corerouter.") else {
                continue;
            };
            let (key, value) = rest.split_once('=').unwrap_or((rest, ""));
            match key {
                "shell" => {
                    let ok = !value.is_empty()
                        && value.len() <= MAX_TTY
                        && value.starts_with("tty")
                        && value.bytes().all(|b| b.is_ascii_alphanumeric());
                    if ok {
                        out.shell = Some(value.to_owned());
                    } else {
                        out.warnings.push(format!(
                            "corerouter.shell={}: not a terminal name (ttyS0, tty1)",
                            clip(value)
                        ));
                    }
                }
                "backend" => match value {
                    "linux" | "virtual" => out.backend = value.to_owned(),
                    _ => out.warnings.push(format!(
                        "corerouter.backend={}: use linux or virtual",
                        clip(value)
                    )),
                },
                _ => out
                    .warnings
                    .push(format!("corerouter.{}: unknown option", clip(key))),
            }
        }
        out
    }
}

/// Error messages never carry more than this much of the input.
fn clip(s: &str) -> String {
    s.chars().take(32).collect()
}

/// The daemon's arguments in the image.
pub fn daemon_args(opts: &BootOptions) -> Vec<String> {
    [
        "--backend",
        &opts.backend,
        "--config-dir",
        CONFIG_DIR,
        "--control",
        &CONTROL_PORT.to_string(),
        "--listen",
        TLS_LISTEN,
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect()
}

/// Restart delay after the daemon dies: 0.5 s doubling up to 30 s, back to
/// the start once it stayed up for `STABLE` (like systemd's
/// `RestartSec`/`StartLimit`, without ever giving up: a router with no
/// control plane is worse than one retrying).
pub struct Backoff {
    failures: u32,
}

pub const STABLE: Duration = Duration::from_secs(60);
const FIRST: Duration = Duration::from_millis(500);
const MAX: Duration = Duration::from_secs(30);

impl Backoff {
    pub const fn new() -> Self {
        Backoff { failures: 0 }
    }

    /// The daemon ran for `ran`; how long to wait before starting it again.
    pub fn after_exit(&mut self, ran: Duration) -> Duration {
        if ran >= STABLE {
            self.failures = 0;
        }
        let delay = FIRST.saturating_mul(1u32 << self.failures.min(6)).min(MAX);
        self.failures = self.failures.saturating_add(1);
        delay
    }
}

/// The block device (`sda2`, `vda2`, `nvme0n1p2`) whose `uevent` says
/// `PARTNAME=<label>`.
pub fn partition_by_label<'a>(
    devices: impl IntoIterator<Item = (&'a str, &'a str)>,
    label: &str,
) -> Option<&'a str> {
    devices.into_iter().find_map(|(name, uevent)| {
        uevent
            .lines()
            .any(|l| l.strip_prefix("PARTNAME=") == Some(label))
            .then_some(name)
    })
}

/// Seconds since the kernel started, from `/proc/uptime`.
pub fn uptime_secs(proc_uptime: &str) -> Option<f64> {
    proc_uptime.split_ascii_whitespace().next()?.parse().ok()
}

/// Memory in use (MemTotal − MemAvailable), KiB, from `/proc/meminfo`.
pub fn mem_used_kib(meminfo: &str) -> Option<u64> {
    let field = |name: &str| {
        meminfo.lines().find_map(|l| {
            let rest = l.strip_prefix(name)?.strip_prefix(':')?;
            rest.split_ascii_whitespace().next()?.parse::<u64>().ok()
        })
    };
    field("MemTotal")?.checked_sub(field("MemAvailable")?)
}

/// What the daemon answers to a `ping` line on the control channel.
pub fn is_pong(line: &str) -> bool {
    line.contains("\"pong\":true") || line.contains("\"pong\": true")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmdline_defaults_and_options() {
        let o = BootOptions::parse("console=ttyS0 root=PARTLABEL=rootfs-a ro quiet");
        assert_eq!(
            o,
            BootOptions {
                shell: None,
                backend: "linux".into(),
                warnings: vec![]
            }
        );
        let o = BootOptions::parse("corerouter.shell=ttyS0 corerouter.backend=virtual");
        assert_eq!(o.shell.as_deref(), Some("ttyS0"));
        assert_eq!(o.backend, "virtual");
        assert!(o.warnings.is_empty());
    }

    #[test]
    fn hostile_cmdline_values_are_refused_and_clipped() {
        let long = "x".repeat(500);
        let o = BootOptions::parse(&format!(
            "corerouter.shell=../../bin/sh corerouter.shell=tty{long} corerouter.backend=rm corerouter.{long}=1 corerouter.shell"
        ));
        assert_eq!(o.shell, None);
        assert_eq!(o.backend, "linux");
        assert_eq!(o.warnings.len(), 5);
        assert!(o.warnings.iter().all(|w| w.len() < 100), "{:?}", o.warnings);
    }

    #[test]
    fn daemon_command_line() {
        let a = daemon_args(&BootOptions::parse(""));
        assert_eq!(
            a.join(" "),
            "--backend linux --config-dir /config --control 7979 --listen 0.0.0.0:8729"
        );
    }

    #[test]
    fn backoff_doubles_caps_and_resets() {
        let mut b = Backoff::new();
        let quick = Duration::from_secs(1);
        let d: Vec<u128> = (0..9).map(|_| b.after_exit(quick).as_millis()).collect();
        assert_eq!(d, [500, 1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000]);
        assert_eq!(b.after_exit(STABLE).as_millis(), 500);
        assert_eq!(b.after_exit(quick).as_millis(), 1000);
    }

    #[test]
    fn config_partition_by_label() {
        let devs = [
            ("vda", "MAJOR=253\nDEVNAME=vda\nDEVTYPE=disk\n"),
            ("vda1", "DEVNAME=vda1\nDEVTYPE=partition\nPARTNAME=efi\n"),
            ("vda3", "DEVNAME=vda3\nDEVTYPE=partition\nPARTNAME=config\n"),
            ("vda4", "PARTNAME=config-old\n"),
        ];
        assert_eq!(partition_by_label(devs, "config"), Some("vda3"));
        assert_eq!(partition_by_label(devs, "rootfs-b"), None);
    }

    #[test]
    fn proc_readings() {
        assert_eq!(uptime_secs("1.53 2.81\n"), Some(1.53));
        assert_eq!(uptime_secs(""), None);
        let mi = "MemTotal:        2014520 kB\nMemFree:         1900000 kB\nMemAvailable:    1950000 kB\n";
        assert_eq!(mem_used_kib(mi), Some(64520));
        assert_eq!(mem_used_kib("MemTotal: 10 kB\n"), None);
        assert!(is_pong(r#"{"id":1,"ok":true,"result":{"pong":true}}"#));
        assert!(!is_pong(r#"{"id":1,"ok":false,"error":"x"}"#));
    }

    #[test]
    fn mounts_are_ordered() {
        let pos = |t: &str| MOUNTS.iter().position(|m| m.target == t);
        assert!(pos("/dev") < pos("/dev/pts"));
        assert!(pos("/sys") < pos("/sys/fs/bpf"));
        assert!(pos("/run").is_some() && pos("/proc") == Some(0));
    }
}

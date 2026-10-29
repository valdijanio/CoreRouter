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
/// The browser GUI in the image (G1.6o), served by `ip.service www-ssl`.
pub const WEB_DIR: &str = "/usr/share/corerouter/web";
/// Writable, persistent configuration (the `config` GPT partition).
pub const CONFIG_DIR: &str = "/config";
/// GPT partition name (PARTLABEL) of the configuration partition.
pub const CONFIG_PARTLABEL: &str = "config";
/// Runtime files (control token); tmpfs.
pub const RUNTIME_DIR: &str = "/run/corerouter";
/// FRR's state directory (`/var/run/frr`, its compiled-in default: the vty
/// sockets and `.pid` files hal-frr reads). `/var/run` is a link to `/run`.
pub const FRR_DIR: &str = "/var/run/frr";
/// The FRR daemons present in the image are started in this order (G1.6c):
/// mgmtd first (the others are its back ends), zebra before the protocols.
/// These are the ones hal-frr configures, plus staticd (mgmtd's static
/// routes back end).
pub const FRR_DAEMONS: &[&str] = &[
    "mgmtd", "zebra", "staticd", "bgpd", "ospfd", "ospf6d", "ldpd", "bfdd",
];
/// Where the FRR daemons are installed.
pub const FRR_SBIN: &str = "/usr/sbin";
/// Marks that the installer's management address (`corerouter.mgmt=`) was
/// applied once, so a later boot does not add it again.
pub const MGMT_DONE: &str = "/config/.installer-mgmt-applied";

/// The arguments of one FRR daemon: no TCP vty (`-P 0`: the sockets in
/// [`FRR_DIR`] only), logs on stdout (the init's log file), a 90 MB netlink
/// receive buffer for zebra (FRR's recommendation for full tables).
pub fn frr_args(daemon: &str) -> Vec<String> {
    let mut a: Vec<String> = ["-P", "0", "--log", "stdout", "--log-level", "notifications"]
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    if daemon == "zebra" {
        a.extend(["-s".to_owned(), "90000000".to_owned()]);
    }
    // G3.6b: CoreRouter's BFD engine is bfdd's data plane (the daemon
    // connects to this socket; bfdd then opens no BFD socket of its own).
    if daemon == "bfdd" {
        a.extend([
            "--dplaneaddr".to_owned(),
            format!("unix:{FRR_DIR}/bfdd_dplane.sock"),
        ]);
    }
    a
}

/// What this boot is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The router (the installed image).
    Router,
    /// The installer ISO's kernel (`corerouter.mode=install`, G1.6c).
    Install,
}

/// A management address set by the installer for the first boot
/// (`corerouter.mgmt=<port>,<address/prefix>[,<gateway>]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mgmt {
    pub interface: String,
    pub address: String,
    pub gateway: Option<String>,
}

impl Mgmt {
    /// Parses and checks the value (hostile: the command line).
    pub fn parse(v: &str) -> Result<Mgmt, String> {
        let mut it = v.split(',');
        let (Some(i), Some(a)) = (it.next(), it.next()) else {
            return Err("use <port>,<address/prefix>[,<gateway>]".into());
        };
        let g = it.next().filter(|g| !g.is_empty());
        if it.next().is_some() {
            return Err("use <port>,<address/prefix>[,<gateway>]".into());
        }
        let port_ok = !i.is_empty()
            && i.len() <= 15
            && i.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
        if !port_ok {
            return Err(format!("'{}' is not a port name", clip(i)));
        }
        let (ip, len) = a
            .split_once('/')
            .ok_or_else(|| format!("'{}': address/prefix", clip(a)))?;
        let ip: std::net::IpAddr = ip
            .parse()
            .map_err(|_| format!("'{}' is not an address", clip(ip)))?;
        let max = if ip.is_ipv4() { 32 } else { 128 };
        if !len.parse::<u8>().is_ok_and(|l| l <= max) {
            return Err(format!("'/{}': prefix length 0..{max}", clip(len)));
        }
        if let Some(g) = g {
            let gw: std::net::IpAddr = g
                .parse()
                .map_err(|_| format!("'{}' is not a gateway address", clip(g)))?;
            if gw.is_ipv4() != ip.is_ipv4() {
                return Err("address and gateway are of different families".into());
            }
        }
        Ok(Mgmt {
            interface: i.to_owned(),
            address: a.to_owned(),
            gateway: g.map(str::to_owned),
        })
    }

    pub fn render(&self) -> String {
        match &self.gateway {
            Some(g) => format!("{},{},{g}", self.interface, self.address),
            None => format!("{},{}", self.interface, self.address),
        }
    }

    /// The commands that set it: the port enabled (a port discovered down
    /// starts disabled), `ip.address.add`, a default route.
    pub fn commands(&self) -> Vec<(&'static str, serde_json::Value)> {
        let mut out = vec![
            (
                "interface.set",
                serde_json::json!({"name": self.interface, "disabled": false}),
            ),
            (
                "ip.address.add",
                serde_json::json!({"address": self.address, "interface": self.interface,
                "comment": "management (installer)"}),
            ),
        ];
        if let Some(g) = &self.gateway {
            let dst = if g.contains(':') { "::/0" } else { "0.0.0.0/0" };
            out.push((
                "ip.route.add",
                serde_json::json!({"dst_address": dst, "gateway": g,
                    "comment": "management (installer)"}),
            ));
        }
        out
    }
}

/// What the console says when `corerouter.mgmt=` is applied (G1.6m): the
/// address, where it came from, and what to do when it was not expected (a
/// new VM that inherited an old one's NVRAM and its boot entry). `ports`:
/// the ports of this boot (empty: unknown).
pub fn mgmt_notice(m: &Mgmt, ports: &[String]) -> String {
    let gw = m
        .gateway
        .as_ref()
        .map(|g| format!(", gateway {g}"))
        .unwrap_or_default();
    let mut s = format!(
        "\nCoreRouter: management address {} on {}{gw}, from the kernel command line \
         (corerouter.mgmt=, put in the UEFI boot entry by the installer). Applied once on this /config.\n\
         Not expected? The VM may have kept an earlier VM's NVRAM: start it with fresh NVRAM \
         (virsh start --reset-nvram; Proxmox: a new EFI disk).",
        m.address, m.interface
    );
    if !ports.is_empty() && !ports.contains(&m.interface) {
        s.push_str(&format!(
            "\nNOT APPLIED: there is no port {} here (ports: {}). The console setup asks for one.",
            m.interface,
            ports.join(", ")
        ));
    }
    s
}

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

/// efivarfs, mounted only on a UEFI boot (the A/B image's boot variables,
/// G1.6b).
pub const EFIVARS: Mount = m(
    "efivarfs",
    "/sys/firmware/efi/efivars",
    "efivarfs",
    "",
    true,
);

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
    pub mode: Mode,
    pub mgmt: Option<Mgmt>,
    /// Complaints about the command line, logged once at boot.
    pub warnings: Vec<String>,
}

const MAX_TTY: usize = 16;

impl BootOptions {
    pub fn parse(cmdline: &str) -> Self {
        let mut out = BootOptions {
            shell: None,
            backend: "linux".into(),
            mode: Mode::Router,
            mgmt: None,
            warnings: Vec::new(),
        };
        for word in cmdline.split_ascii_whitespace() {
            let Some(rest) = word.strip_prefix("corerouter.") else {
                continue;
            };
            let (key, value) = rest.split_once('=').unwrap_or((rest, ""));
            match key {
                // The A/B slot of a boot entry, read by corerouter-sysupdate.
                "slot" => {}
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
                "mode" => match value {
                    "install" => out.mode = Mode::Install,
                    "router" => out.mode = Mode::Router,
                    _ => out.warnings.push(format!(
                        "corerouter.mode={}: use install or router",
                        clip(value)
                    )),
                },
                "mgmt" => match Mgmt::parse(value) {
                    Ok(m) => out.mgmt = Some(m),
                    Err(e) => out.warnings.push(format!("corerouter.mgmt: {e}")),
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

/// The daemon's arguments in the image (`frr`: FRR is in the image and the
/// init runs it, G1.6c).
pub fn daemon_args(opts: &BootOptions, frr: bool) -> Vec<String> {
    let mut a: Vec<String> = [
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
    .collect();
    // G1.6o: web access (https://<router>/) on in a config made at first boot.
    a.extend(["--web-files", WEB_DIR, "--web-factory-on"].map(str::to_owned));
    if frr {
        a.extend(["--frr".to_owned(), FRR_DIR.to_owned()]);
    }
    a
}

/// The uid and gid of `user` in `/etc/passwd`.
pub fn passwd_ids(passwd: &str, user: &str) -> Option<(u32, u32)> {
    passwd.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == user).then_some(())?;
        let _ = f.next()?;
        Some((f.next()?.parse().ok()?, f.next()?.parse().ok()?))
    })
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
                mode: Mode::Router,
                mgmt: None,
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
        let a = daemon_args(&BootOptions::parse(""), false);
        assert_eq!(
            a.join(" "),
            "--backend linux --config-dir /config --control 7979 --listen 0.0.0.0:8729 \
             --web-files /usr/share/corerouter/web --web-factory-on"
        );
        let a = daemon_args(&BootOptions::parse(""), true);
        assert!(a.join(" ").ends_with("--frr /var/run/frr"));
        assert_eq!(
            frr_args("zebra").join(" "),
            "-P 0 --log stdout --log-level notifications -s 90000000"
        );
        assert!(!frr_args("bgpd").contains(&"-s".to_owned()));
        assert!(
            frr_args("bfdd")
                .join(" ")
                .ends_with("--dplaneaddr unix:/var/run/frr/bfdd_dplane.sock")
        );
        assert_eq!(FRR_DAEMONS.first(), Some(&"mgmtd"));
    }

    #[test]
    fn install_mode_and_management_address() {
        let o = BootOptions::parse(
            "console=ttyS0 corerouter.mode=install corerouter.mgmt=eth0,10.0.2.15/24,10.0.2.2",
        );
        assert_eq!(o.mode, Mode::Install);
        let m = o.mgmt.unwrap();
        assert_eq!(m.render(), "eth0,10.0.2.15/24,10.0.2.2");
        let c = m.commands();
        assert_eq!(c[0].0, "interface.set");
        assert_eq!(c[0].1["disabled"], false);
        assert_eq!(c[1].0, "ip.address.add");
        assert_eq!(c[1].1["interface"], "eth0");
        assert_eq!(c[2].1["dst_address"], "0.0.0.0/0");
        let v6 = Mgmt::parse("ether1,2001:db8::2/64,2001:db8::1").unwrap();
        assert_eq!(v6.commands()[2].1["dst_address"], "::/0");
        assert_eq!(
            Mgmt::parse("eth0,192.0.2.1/24").unwrap().commands().len(),
            2
        );
        for bad in [
            "",
            "eth0",
            "eth0,10.0.0.1",
            "eth0,10.0.0.1/33",
            "eth0,10.0.0.1/24,::1",
            "eth 0,10.0.0.1/24",
            "eth0,10.0.0.1/24,10.0.0.254,x",
            "../../x,10.0.0.1/24",
        ] {
            assert!(Mgmt::parse(bad).is_err(), "{bad}");
        }
        let o = BootOptions::parse("corerouter.mode=rescue corerouter.mgmt=nope");
        assert_eq!(o.mode, Mode::Router);
        assert_eq!(o.warnings.len(), 2);
    }

    #[test]
    fn management_notice_says_where_it_came_from() {
        let m = Mgmt::parse("ether1,192.0.2.10/24,192.0.2.1").unwrap();
        let ports = vec!["ether1".to_owned(), "ether2".to_owned()];
        let t = mgmt_notice(&m, &ports);
        assert!(
            t.contains("192.0.2.10/24 on ether1, gateway 192.0.2.1"),
            "{t}"
        );
        assert!(t.contains("corerouter.mgmt=") && t.contains("--reset-nvram"));
        assert!(!t.contains("NOT APPLIED"));
        let m = Mgmt::parse("eth7,192.0.2.10/24").unwrap();
        let t = mgmt_notice(&m, &ports);
        assert!(
            t.contains("NOT APPLIED: there is no port eth7 here (ports: ether1, ether2)"),
            "{t}"
        );
        assert!(!mgmt_notice(&m, &[]).contains("NOT APPLIED"));
    }

    #[test]
    fn passwd_lookup() {
        let p =
            "root:x:0:0:root:/root:/bin/sh\nfrr:x:100:101:FRR user priv:/var/run/frr:/bin/false\n";
        assert_eq!(passwd_ids(p, "frr"), Some((100, 101)));
        assert_eq!(passwd_ids(p, "nobody"), None);
        assert_eq!(passwd_ids("frr:x:a:b", "frr"), None);
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

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
/// G1.6i: the FRR daemons that always run (mgmtd and its back ends zebra
/// and staticd); the others run only while the daemon names them in
/// [`FRR_WANTED`] (`hal-frr`'s `on_demand`).
pub const FRR_ALWAYS: &[&str] = &["mgmtd", "zebra", "staticd"];
/// Where the daemon writes the protocol daemons its config uses (tmpfs: a
/// reboot starts with [`FRR_ALWAYS`] and the daemon's first sync asks again).
pub const FRR_WANTED: &str = "/run/corerouter/frr-daemons";
/// Longest [`FRR_WANTED`] read (its five names fit in 100 bytes).
pub const FRR_WANTED_MAX: u64 = 4096;

/// The FRR daemons to run for the text of [`FRR_WANTED`] (hostile: only
/// names of [`FRR_DAEMONS`] count), in start order; [`FRR_ALWAYS`] always.
pub fn frr_wanted(text: &str) -> Vec<&'static str> {
    let listed: Vec<&str> = text.lines().map(str::trim).collect();
    FRR_DAEMONS
        .iter()
        .copied()
        .filter(|d| FRR_ALWAYS.contains(d) || listed.contains(d))
        .collect()
}
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
    /// The installer ISO's console installer (`corerouter.mode=install`,
    /// G1.6c): also what the live ISO falls back to.
    Install,
    /// The ISO's default (`corerouter.mode=live`, G1.6y): the image from RAM,
    /// `/config` on a tmpfs, nothing written until an install is asked for.
    Live,
}

/// The argument the first stage of the live ISO passes to `corerouter-init`
/// on the image's root: this boot already moved there (G1.6y).
pub const LIVE_STAGE2: &str = "--live-root";
/// Below this `MemTotal` the ISO stays on the console installer (G1.6y). The
/// root and the driver modules live in RAM, and a login with a password
/// (Argon2) takes the daemon to ~128 MiB: without room for both that is an
/// OOM kill at every login, and the install in progress goes with the daemon.
/// The root was 47 MiB when 320 MiB of RAM became the least (G1.6za); with the
/// Wi-Fi firmware it is 86 MiB (G1.30). Then 320 MiB kills the daemon at the
/// first login with a password; 384 MiB installs most of the time, with 300
/// of its 329 MiB in use at the worst moment, and failed 1 time in 8; 448 MiB
/// is the least (**medido**). A machine shows less than it has, what the
/// kernel and the firmware keep: under OVMF, 329 MiB for 384 MiB and 359 MiB
/// for 416 MiB (**medido**).
pub const LIVE_MIN_RAM_KIB: u64 = 370 * 1024;
/// The live image's host name.
pub const LIVE_HOSTNAME: &str = "corerouter-live";

/// `MemTotal` of `/proc/meminfo`, in KiB.
pub fn mem_total_kib(meminfo: &str) -> Option<u64> {
    meminfo
        .lines()
        .find_map(|l| l.strip_prefix("MemTotal:"))?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

/// What one port of the live image still needs to get an address by DHCP
/// (G1.6y): in the configuration, enabled, with a client (client only, a
/// route of low preference per port, so the first one wins while it has a
/// lease, and a name the network's operator recognizes). `i`: the port's
/// place among the machine's.
///
/// G1.6ze: decided from what the daemon lists (`interface.list`,
/// `ip.dhcp-client.list`), never by trying. A card plugged in is in the
/// configuration only seconds later (the daemon adopts a port after it kept
/// its name for three polls), and the `interface.set` sent meanwhile left ten
/// error lines in the router's log; PID 1 has just named the port, so it
/// adopts it itself. A port plugged in again has its client already.
/// `None`: the daemon does not list the port yet.
pub fn live_port_commands(
    port: &str,
    i: usize,
    interfaces: &serde_json::Value,
    clients: &serde_json::Value,
) -> Option<Vec<(&'static str, serde_json::Value)>> {
    let named =
        |v: &serde_json::Value, key: &str| v.get(key).and_then(|n| n.as_str()) == Some(port);
    let row = interfaces.as_array()?.iter().find(|r| named(r, "name"))?;
    let mut out = Vec::new();
    // A row of the platform, not of the configuration (`managed: false`):
    // adopted with the kernel's state, down for a card just plugged in.
    let adopted = row.get("managed").and_then(serde_json::Value::as_bool) == Some(true);
    if !adopted {
        out.push((
            "interface.ethernet.adopt",
            serde_json::json!({"name": port}),
        ));
    }
    if !adopted || row.get("disabled").and_then(serde_json::Value::as_bool) != Some(false) {
        out.push((
            "interface.set",
            serde_json::json!({"name": port, "disabled": false}),
        ));
    }
    let has_client = clients
        .as_array()
        .is_some_and(|c| c.iter().any(|c| named(c, "interface")));
    if !has_client {
        out.push((
            "ip.dhcp-client.add",
            serde_json::json!({
                "interface": port,
                "host_name": LIVE_HOSTNAME,
                "default_route_distance": 200 + i.min(50),
                "comment": "live image",
            }),
        ));
    }
    Some(out)
}

/// `ether3` → 2, the route preference of its DHCP client.
pub fn port_index(port: &str) -> usize {
    port.strip_prefix("ether")
        .and_then(|n| n.parse::<usize>().ok())
        .map_or(0, |n| n.saturating_sub(1))
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

/// The commands to run on the first boot, and the line for the console.
pub type FirstBootPlan = (Vec<(&'static str, serde_json::Value)>, String);

/// What the install from the live image left for the first boot (G1.6y): the
/// commands to run, and what to tell the console. Read from the new `/config`.
pub fn first_boot_commands(text: &str) -> Result<FirstBootPlan, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    let mut out = Vec::new();
    let mut said = String::from("no management port chosen");
    if let Some(m) = v.get("mgmt").filter(|m| !m.is_null()) {
        let s = |k: &str| m.get(k).and_then(serde_json::Value::as_str);
        let port = s("port").ok_or("mgmt: no port")?;
        out.push((
            "interface.set",
            serde_json::json!({"name": port, "disabled": false}),
        ));
        if let Some(address) = s("address") {
            let mg = Mgmt {
                interface: port.to_owned(),
                address: address.to_owned(),
                gateway: s("gateway").map(str::to_owned),
            };
            out.extend(
                mg.commands()
                    .into_iter()
                    .filter(|(c, _)| *c != "interface.set"),
            );
            said = format!("management: {address} on {port}");
        } else {
            out.push((
                "ip.dhcp-client.add",
                serde_json::json!({"interface": port, "comment": "management (installer)"}),
            ));
            said = format!("management: DHCP on {port} (the address may change)");
        }
        if let Some(dns) = m
            .get("dns")
            .and_then(serde_json::Value::as_array)
            .filter(|d| !d.is_empty())
        {
            out.push(("ip.dns.set", serde_json::json!({"servers": dns})));
        }
    }
    if let Some(h) = v
        .get("admin_password_hash")
        .and_then(serde_json::Value::as_str)
    {
        out.push((
            "user.set",
            serde_json::json!({"name": "admin", "password_hash": h}),
        ));
    }
    Ok((out, said))
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
         (corerouter.mgmt=, put on the boot line by the installer). Applied once on this /config.\n\
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

/// G1.6zx: the records the previous boot's panic left (ERST, UEFI
/// variables), which the daemon's `crash-log` service saves and erases.
/// Mounted when the kernel has it ([`has_fs`]): the installer's has not.
pub const PSTORE: Mount = m("pstore", "/sys/fs/pstore", "pstore", "", true);

/// The kernel knows filesystem `fs` (`/proc/filesystems`: `nodev\tpstore`).
pub fn has_fs(proc_filesystems: &str, fs: &str) -> bool {
    proc_filesystems
        .lines()
        .any(|l| l.split_ascii_whitespace().last() == Some(fs))
}

/// G1.6zx: on a real machine a CPU stuck in the kernel (soft lockup, 20 s)
/// or with its interrupts off (hard lockup, 10 s) panics, and `panic=10`
/// reboots: the router comes back and the next boot shows the trace. Not in
/// a virtual machine, where the host may stop a vCPU for that long; not
/// over what the command line set (`system.tuning.boot`). The operator
/// changes them at run time in `/system tuning`.
pub fn lockup_panic(cpuinfo: &str, cmdline: &str) -> Vec<(&'static str, &'static str)> {
    if virtual_machine(cpuinfo) {
        return Vec::new();
    }
    let given = |k: &str| {
        cmdline
            .split_ascii_whitespace()
            .any(|w| w.split_once('=').is_some_and(|(n, _)| n == k))
    };
    [
        ("softlockup_panic", "/proc/sys/kernel/softlockup_panic"),
        ("hardlockup_panic", "/proc/sys/kernel/hardlockup_panic"),
    ]
    .into_iter()
    .filter(|(k, _)| !given(k))
    .map(|(_, p)| (p, "1"))
    .collect()
}

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
    /// G1.6j: load the drivers of the cards found (`corerouter.modules=off`:
    /// only what is built into the kernel).
    pub modules: bool,
    /// G1.6zf: look for the motherboard's sensor chip (`corerouter.sensors=`).
    pub sensors: Sensors,
    /// G1.30: that many simulated Wi-Fi radios (`corerouter.hwsim=2`,
    /// `mac80211_hwsim`), for a test of the image where there is no card.
    pub hwsim: Option<u8>,
    /// G1.30: links the router must never touch, as the daemon's
    /// `--unmanaged` takes them (`corerouter.unmanaged=wifi1,eth9`): a port
    /// lent to something else on the machine. The image's own test keeps the
    /// radio of its access point out of the router's hands with it.
    pub unmanaged: Option<String>,
    /// Complaints about the command line, logged once at boot.
    pub warnings: Vec<String>,
}

/// G1.6zf: whether PID 1 loads the Super-I/O drivers (fans, voltages, board
/// temperatures). The chips are not enumerated: a driver finds its chip by
/// writing an unlock key to I/O ports 0x2e and 0x4e.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sensors {
    /// On a real machine, not in a virtual one (nothing is there to find).
    Auto,
    /// In a virtual machine too.
    On,
    /// Never: for the board where looking does harm.
    Off,
}

impl Sensors {
    /// Look for the chips on a machine with this `/proc/cpuinfo`?
    pub fn wanted(self, cpuinfo: &str) -> bool {
        match self {
            Sensors::On => true,
            Sensors::Off => false,
            Sensors::Auto => !virtual_machine(cpuinfo),
        }
    }
}

/// The CPU says it runs under a hypervisor (CPUID.1:ECX[31], the
/// `hypervisor` flag of `/proc/cpuinfo`: KVM, VMware, Hyper-V, Xen HVM,
/// VirtualBox, bhyve all set it).
pub fn virtual_machine(cpuinfo: &str) -> bool {
    cpuinfo
        .lines()
        .find_map(|l| l.strip_prefix("flags"))
        .is_some_and(|flags| flags.split_ascii_whitespace().any(|f| f == "hypervisor"))
}

const MAX_TTY: usize = 16;
/// Simulated radios a test may ask for.
const MAX_HWSIM: u8 = 8;
/// The longest `corerouter.unmanaged=` list.
const MAX_UNMANAGED: usize = 256;

impl BootOptions {
    pub fn parse(cmdline: &str) -> Self {
        let mut out = BootOptions {
            shell: None,
            backend: "linux".into(),
            mode: Mode::Router,
            mgmt: None,
            modules: true,
            sensors: Sensors::Auto,
            hwsim: None,
            unmanaged: None,
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
                    "live" => out.mode = Mode::Live,
                    "router" => out.mode = Mode::Router,
                    _ => out.warnings.push(format!(
                        "corerouter.mode={}: use install, live or router",
                        clip(value)
                    )),
                },
                "modules" => match value {
                    "on" => out.modules = true,
                    "off" => out.modules = false,
                    _ => out
                        .warnings
                        .push(format!("corerouter.modules={}: use on or off", clip(value))),
                },
                "unmanaged" => {
                    let ok = !value.is_empty()
                        && value.len() <= MAX_UNMANAGED
                        && value.bytes().all(|b| {
                            b.is_ascii_alphanumeric()
                                || matches!(b, b',' | b'-' | b'_' | b'.' | b'*')
                        });
                    if ok {
                        out.unmanaged = Some(value.to_owned());
                    } else {
                        out.warnings.push(format!(
                            "corerouter.unmanaged={}: use link names separated by commas",
                            clip(value)
                        ));
                    }
                }
                "hwsim" => match value.parse::<u8>() {
                    Ok(n) if (1..=MAX_HWSIM).contains(&n) => out.hwsim = Some(n),
                    _ => out.warnings.push(format!(
                        "corerouter.hwsim={}: use a number of radios, 1 to {MAX_HWSIM}",
                        clip(value)
                    )),
                },
                "sensors" => match value {
                    "auto" => out.sensors = Sensors::Auto,
                    "on" => out.sensors = Sensors::On,
                    "off" => out.sensors = Sensors::Off,
                    _ => out.warnings.push(format!(
                        "corerouter.sensors={}: use auto, on or off",
                        clip(value)
                    )),
                },
                "mgmt" => match Mgmt::parse(value) {
                    Ok(m) => out.mgmt = Some(m),
                    Err(e) => out.warnings.push(format!("corerouter.mgmt: {e}")),
                },
                // G1.6zg: the consoles' colour, read by `style::Color`.
                "color" => {
                    if !matches!(value, "on" | "screen" | "off") {
                        out.warnings.push(format!(
                            "corerouter.color={}: use on, screen or off",
                            clip(value)
                        ));
                    }
                }
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
        a.extend(["--frr", FRR_DIR, "--frr-daemons", FRR_WANTED].map(str::to_owned));
    }
    if opts.mode == Mode::Live {
        a.push("--live".to_owned());
    }
    if let Some(names) = &opts.unmanaged {
        a.extend(["--unmanaged".to_owned(), names.clone()]);
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

/// Longest message PID 1 writes to `/dev/kmsg` (a record holds about
/// 1 KiB; the kernel refuses a longer write).
pub const KMSG_MAX: usize = 900;

/// `msg` as one `/dev/kmsg` record (G1.29f): facility user, level notice
/// (`<13>`, below the console level of `quiet`, so the console does not
/// show the line twice), tagged `corerouter-init[1]` like a syslog line
/// (the OS log takes the unit and the pid from it), on one line and cut to
/// [`KMSG_MAX`] bytes on a character boundary.
pub fn kmsg_record(msg: &str) -> Vec<u8> {
    let mut out = String::from("<13>corerouter-init[1]: ");
    for c in msg.chars().map(|c| if c.is_control() { ' ' } else { c }) {
        if out.len() + c.len_utf8() > KMSG_MAX {
            break;
        }
        out.push(c);
    }
    out.push('\n');
    out.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmanaged_option() {
        assert_eq!(BootOptions::parse("quiet").unmanaged, None);
        let o = BootOptions::parse("corerouter.unmanaged=wifi1,eth9,veth*");
        assert_eq!(o.unmanaged.as_deref(), Some("wifi1,eth9,veth*"));
        let a = daemon_args(&o, false);
        let at = a.iter().position(|x| x == "--unmanaged").unwrap();
        assert_eq!(a[at + 1], "wifi1,eth9,veth*");
        assert!(!daemon_args(&BootOptions::parse(""), false).contains(&"--unmanaged".to_owned()));
        let long = "a".repeat(300);
        for bad in ["", "a=b", "x;rm", long.as_str(), "a/b", "\"q\""] {
            let o = BootOptions::parse(&format!("corerouter.unmanaged={bad}"));
            assert_eq!(o.unmanaged, None, "{bad}");
        }
    }

    #[test]
    fn hwsim_option() {
        assert_eq!(BootOptions::parse("quiet").hwsim, None);
        assert_eq!(BootOptions::parse("corerouter.hwsim=2").hwsim, Some(2));
        for bad in ["0", "9", "-1", "two", "", "2x", "300"] {
            let o = BootOptions::parse(&format!("corerouter.hwsim={bad}"));
            assert_eq!(o.hwsim, None, "{bad}");
            assert_eq!(o.warnings.len(), 1, "{bad}");
        }
    }

    #[test]
    fn modules_option() {
        assert!(BootOptions::parse("quiet").modules);
        assert!(!BootOptions::parse("corerouter.modules=off").modules);
        assert!(BootOptions::parse("corerouter.modules=on").modules);
        // G1.6zf: the motherboard's sensor chips.
        assert_eq!(BootOptions::parse("").sensors, Sensors::Auto);
        assert_eq!(
            BootOptions::parse("corerouter.sensors=off").sensors,
            Sensors::Off
        );
        assert_eq!(
            BootOptions::parse("corerouter.sensors=on").sensors,
            Sensors::On
        );
        let bad = BootOptions::parse("corerouter.sensors=lax");
        assert_eq!(bad.sensors, Sensors::Auto);
        assert_eq!(bad.warnings.len(), 1);
        let bad = BootOptions::parse("corerouter.modules=maybe");
        assert!(bad.modules);
        assert_eq!(bad.warnings.len(), 1);
    }

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
                modules: true,
                sensors: Sensors::Auto,
                hwsim: None,
                unmanaged: None,
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
    fn frr_runs_the_base_daemons_and_what_the_file_names() {
        assert_eq!(frr_wanted(""), ["mgmtd", "zebra", "staticd"]);
        // The daemon's file: a comment, names in any order, junk ignored.
        let text = "# FRR daemons\nbfdd\nbgpd\n../../bin/sh\nzebra\n  ospfd  \n";
        assert_eq!(
            frr_wanted(text),
            ["mgmtd", "zebra", "staticd", "bgpd", "ospfd", "bfdd"]
        );
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
        assert!(
            a.join(" ")
                .ends_with("--frr /var/run/frr --frr-daemons /run/corerouter/frr-daemons")
        );
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
    fn live_mode_is_one_more_mode_and_tells_the_daemon() {
        let o = BootOptions::parse("console=ttyS0 corerouter.mode=live quiet");
        assert_eq!(o.mode, Mode::Live);
        assert!(o.warnings.is_empty());
        assert!(daemon_args(&o, false).contains(&"--live".to_owned()));
        let r = BootOptions::parse("corerouter.slot=a");
        assert!(!daemon_args(&r, false).contains(&"--live".to_owned()));
        // G1.6za: `corerouter.modules=off` holds in the live image too.
        assert!(o.modules);
        assert!(!BootOptions::parse("corerouter.mode=live corerouter.modules=off").modules);
    }

    /// G1.6zf: the Super-I/O drivers poke I/O ports to find their chip; a
    /// virtual machine has none, and the operator can say never.
    #[test]
    fn sensor_chips_are_looked_for_on_real_machines_only() {
        let real = "processor\t: 0\nmodel name\t: 13th Gen Intel(R) Core(TM) i5\nflags\t\t: fpu vme de pse tsc msr dtherm ida arat\n";
        let vm = "processor\t: 0\nflags\t\t: fpu vme hypervisor lahf_lm\n";
        assert!(!virtual_machine(real));
        assert!(virtual_machine(vm));
        // Not a word of another line, nor a part of another flag.
        assert!(!virtual_machine(
            "model name\t: hypervisor\nflags\t\t: fpu nohypervisor\n"
        ));
        assert!(!virtual_machine(""));
        assert!(Sensors::Auto.wanted(real));
        assert!(!Sensors::Auto.wanted(vm));
        assert!(Sensors::On.wanted(vm));
        assert!(!Sensors::Off.wanted(real));
        // No /proc/cpuinfo read: a real machine is assumed (the drivers
        // themselves find nothing where there is nothing).
        assert!(Sensors::Auto.wanted(""));
    }

    #[test]
    fn live_memory_floor_and_dhcp_on_every_port() {
        assert_eq!(
            mem_total_kib("MemFree: 1 kB\nMemTotal:  1024 kB\n"),
            Some(1024)
        );
        assert_eq!(mem_total_kib("garbage"), None);
        assert_eq!(mem_total_kib("MemTotal: x kB"), None);
        // A port seeded at boot, disabled (found down), no client yet.
        let ifaces = serde_json::json!([
            {"name": "lo", "managed": true, "disabled": false},
            {"name": "ether1", "managed": true, "disabled": true},
            {"name": "ether2", "managed": true, "disabled": true},
        ]);
        let none = serde_json::json!([]);
        let c = live_port_commands("ether1", 0, &ifaces, &none).unwrap();
        let ids: Vec<&str> = c.iter().map(|x| x.0).collect();
        assert_eq!(ids, ["interface.set", "ip.dhcp-client.add"]);
        assert_eq!(
            c[0].1,
            serde_json::json!({"name": "ether1", "disabled": false})
        );
        assert_eq!(c[1].1["interface"], "ether1");
        assert_eq!(c[1].1["default_route_distance"], 200);
        let c = live_port_commands("ether2", 1, &ifaces, &none).unwrap();
        assert_eq!(c[1].1["default_route_distance"], 201);
        // Far more ports than a distance can tell apart: still a valid one.
        let c = live_port_commands("ether2", 1023, &ifaces, &none).unwrap();
        assert_eq!(c[1].1["default_route_distance"], 250);
    }

    /// G1.6ze: the notebook's log had ten `interface.set` refused ("no
    /// interface 'ether2'") between the USB adapter's name and its adoption.
    /// Nothing is sent that the daemon would refuse.
    #[test]
    fn a_port_plugged_into_the_live_image_is_adopted_before_anything_is_set() {
        let ids = |c: &[(&'static str, serde_json::Value)]| -> Vec<&'static str> {
            c.iter().map(|x| x.0).collect()
        };
        let none = serde_json::json!([]);
        // Named by PID 1, not listed by the daemon yet: wait, send nothing.
        let before = serde_json::json!([{"name": "ether1", "managed": true, "disabled": false}]);
        assert!(live_port_commands("ether2", 1, &before, &none).is_none());
        // Garbage instead of a list: the same.
        for bad in [
            serde_json::json!(null),
            serde_json::json!({"name": "ether2"}),
        ] {
            assert!(live_port_commands("ether2", 1, &bad, &none).is_none());
        }
        // Listed as the platform's (not adopted): adoption first.
        let plugged = serde_json::json!([
            {"name": "ether1", "managed": true, "disabled": false},
            {"name": "ether2", "managed": false, "disabled": false,
             "unmanaged_reason": "not in the configuration (appeared after boot)"},
        ]);
        let c = live_port_commands("ether2", 1, &plugged, &none).unwrap();
        assert_eq!(
            ids(&c),
            [
                "interface.ethernet.adopt",
                "interface.set",
                "ip.dhcp-client.add"
            ]
        );
        assert_eq!(c[0].1, serde_json::json!({"name": "ether2"}));
        // The daemon adopted it first (its tick): only what is missing.
        let adopted = serde_json::json!([{"name": "ether2", "managed": true, "disabled": true}]);
        let c = live_port_commands("ether2", 1, &adopted, &none).unwrap();
        assert_eq!(ids(&c), ["interface.set", "ip.dhcp-client.add"]);
        // Plugged in again: in the configuration, enabled, its client kept.
        let again = serde_json::json!([{"name": "ether2", "managed": true, "disabled": false}]);
        let client = serde_json::json!([{"id": "*1", "interface": "ether2"}]);
        assert!(
            live_port_commands("ether2", 1, &again, &client)
                .unwrap()
                .is_empty()
        );
        // Another port's client is not this one's.
        let other = serde_json::json!([{"id": "*1", "interface": "ether1"}]);
        assert_eq!(
            ids(&live_port_commands("ether2", 1, &again, &other).unwrap()),
            ["ip.dhcp-client.add"]
        );
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
    fn pstore_and_lockup_panic() {
        let fs = "nodev\tsysfs\nnodev\tpstore\n\text4\n";
        assert!(has_fs(fs, "pstore") && has_fs(fs, "ext4"));
        assert!(!has_fs("nodev\tpstorex\n", "pstore"));
        let real = "flags\t\t: fpu vme lahf_lm\n";
        let vm = "flags\t\t: fpu hypervisor\n";
        assert_eq!(
            lockup_panic(real, "panic=10 quiet"),
            [
                ("/proc/sys/kernel/softlockup_panic", "1"),
                ("/proc/sys/kernel/hardlockup_panic", "1")
            ]
        );
        assert!(lockup_panic(vm, "panic=10").is_empty());
        assert_eq!(
            lockup_panic(real, "softlockup_panic=0 quiet"),
            [("/proc/sys/kernel/hardlockup_panic", "1")]
        );
    }

    #[test]
    fn mounts_are_ordered() {
        let pos = |t: &str| MOUNTS.iter().position(|m| m.target == t);
        assert!(pos("/dev") < pos("/dev/pts"));
        assert!(pos("/sys") < pos("/sys/fs/bpf"));
        assert!(pos("/run").is_some() && pos("/proc") == Some(0));
    }

    #[test]
    fn kmsg_record_is_one_tagged_line_that_fits() {
        assert_eq!(
            kmsg_record("port names: eth0 → ether4: File exists"),
            "<13>corerouter-init[1]: port names: eth0 → ether4: File exists\n".as_bytes()
        );
        let r = kmsg_record(&format!("a\nb{}", "é".repeat(1000)));
        let t = String::from_utf8(r).unwrap();
        assert!(t.len() <= KMSG_MAX + 1, "{}", t.len());
        assert!(t.starts_with("<13>corerouter-init[1]: a b"), "{t}");
        assert_eq!(t.matches('\n').count(), 1);
    }

    #[test]
    fn the_install_tells_the_first_boot_what_to_do() {
        let (c, said) = first_boot_commands(
            r#"{"mgmt":{"port":"ether2","address":null,"gateway":null,"dns":[]}}"#,
        )
        .unwrap();
        let ids: Vec<&str> = c.iter().map(|x| x.0).collect();
        assert_eq!(ids, ["interface.set", "ip.dhcp-client.add"]);
        assert!(said.contains("DHCP on ether2"), "{said}");
        let (c, said) = first_boot_commands(
            r#"{"mgmt":{"port":"ether1","address":"10.0.0.2/24","gateway":"10.0.0.1","dns":["1.1.1.1"]},"admin_password_hash":"$argon2id$x"}"#,
        )
        .unwrap();
        let ids: Vec<&str> = c.iter().map(|x| x.0).collect();
        assert_eq!(
            ids,
            [
                "interface.set",
                "ip.address.add",
                "ip.route.add",
                "ip.dns.set",
                "user.set"
            ]
        );
        assert!(said.contains("10.0.0.2/24 on ether1"), "{said}");
        let (c, _) = first_boot_commands("{}").unwrap();
        assert!(c.is_empty());
        for bad in ["not json", r#"{"mgmt":{"address":"10.0.0.2/24"}}"#] {
            assert!(first_boot_commands(bad).is_err(), "{bad}");
        }
    }

    /// G1.6za: a port that shows up late gets the same client as the others.
    #[test]
    fn a_late_port_gets_its_place_in_the_route_preference() {
        assert_eq!(port_index("ether1"), 0);
        assert_eq!(port_index("ether4"), 3);
        assert_eq!(port_index("ether0"), 0);
        assert_eq!(port_index("eth2"), 0);
        assert_eq!(port_index("ether999999999999999999999"), 0);
    }
}

//! G0.26: `cargo xtask vm-lab <subcommand>` — a libvirt VM where agents are
//! root, for the tests that need it (XDP on `virtio_net`, the BNG lab with
//! `pppd`). Root stays inside the VM: nothing here runs `sudo` on the host.
//!
//! The VM is `corerouter-lab` on `qemu:///system` (the user is in group
//! `libvirt`), on libvirt's existing `default` NAT network for SSH and apt.
//! Test links are pairs of virtio NICs wired to each other through UDP
//! sockets on the host's loopback (`wire<n>a` ↔ `wire<n>b`): no host bridge,
//! no iptables. Everything lives in `vm/` of the main checkout (gitignored),
//! shared by every worktree: the verified Ubuntu cloud image, a thin qcow2
//! overlay, the cloud-init seed and an SSH key made for the lab only.
//! Details and limits: `docs/vm-lab.md`.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use sha2::{Digest, Sha256};

use crate::Outcome;

const NAME: &str = "corerouter-lab";
const URI: &str = "qemu:///system";
const IMAGE: &str = "noble-server-cloudimg-amd64.img";
const IMAGE_URL: &str = "https://cloud-images.ubuntu.com/noble/current/";
/// The management NIC's MAC: how `domifaddr` finds the VM's address.
const MGMT_MAC: &str = "52:54:00:c0:72:01";
/// UDP ports on 127.0.0.1 behind the wires (two per NIC pair).
const WIRE_PORT_BASE: u16 = 47_210;
const MAX_WIRES: u32 = 4;
const USER: &str = "lab";
/// Toolchains, sources and build caches inside the VM.
const RUST_ENV: &str = "/etc/profile.d/corerouter-rust.sh";
const LAB_ROOT: &str = "/srv/lab";
const PACKAGES: &[&str] = &[
    "build-essential",
    "clang",
    "llvm",
    "pkg-config",
    "iproute2",
    "tcpdump",
    "ppp",
    "pppoe",
    "ethtool",
    "nftables",
    "rsync",
    "git",
    "curl",
    "jq",
    "qemu-guest-agent",
    // The 24.04 GA kernel (6.8) rejects our XDP program ("combined stack
    // size of 3 calls is 544. Too large", **measured**); HWE is 7.0, like
    // the host.
    "linux-generic-hwe-24.04",
];

const HELP: &str = "usage: cargo xtask vm-lab <subcommand>
  create [--cpus N] [--memory MiB] [--disk GiB] [--wires N]
                    download + verify the Ubuntu 24.04 image, make the VM, provision
                    it (packages, rustup) and take the `clean` snapshot
                    (defaults: 8 vCPUs, 8192 MiB, 20 GiB thin, 1 wire = 2 test NICs)
  up | down         start (and wait for SSH) | shut down
  status            state, address, snapshots, disk use
  ssh [cmd...]      shell (or one command) as user `lab`; `sudo` works inside
  sync              rsync this worktree to /srv/lab/<worktree>/src (no target*, .git)
  put <file...>     copy host files into /srv/lab/inbox/ (a .deb, a capture)
  run [--no-sync] -- <cmd...>
                    sync, then run <cmd> as root in /srv/lab/<worktree>/src with
                    CARGO_TARGET_DIR=/srv/lab/<worktree>/target (kept: incremental)
  snapshot [name]   save the disk (default `clean`; the VM is shut down for it)
  reset [name]      throw the disk back to a snapshot (default `clean`) and boot
  destroy           delete the VM and its overlay (the cached image stays)";

/// Entry point: `args` are what follows `vm-lab`.
pub fn main(root: &Path, args: &[String]) -> Outcome {
    let lab = match Lab::new(root) {
        Ok(l) => l,
        Err(e) => return Outcome::Fail(e),
    };
    let (sub, rest) = match args.split_first() {
        Some((s, r)) => (s.as_str(), r),
        None => ("", &[][..]),
    };
    let result = match sub {
        "create" => lab.create(rest),
        "up" => lab.up(),
        "down" => lab.down(),
        "status" => lab.status(),
        "ssh" => lab.ssh_interactive(rest),
        "sync" => lab.up().and_then(|()| lab.sync()),
        "put" => lab.put(rest),
        "run" => lab.run(rest),
        "snapshot" => lab.snapshot(rest.first().map_or("clean", String::as_str)),
        "reset" => lab.reset(rest.first().map_or("clean", String::as_str)),
        "destroy" => lab.destroy(),
        "" | "-h" | "--help" | "help" => {
            eprintln!("{HELP}");
            return Outcome::Ok;
        }
        other => Err(format!("unknown subcommand '{other}'\n{HELP}")),
    };
    match result {
        Ok(()) => Outcome::Ok,
        Err(e) => Outcome::Fail(e),
    }
}

struct Lab {
    /// The worktree being worked on (what `sync` copies).
    root: PathBuf,
    /// `vm/` of the main checkout, or `$COREROUTER_VM_DIR`.
    dir: PathBuf,
}

struct Spec {
    cpus: u32,
    memory_mib: u32,
    disk_gib: u32,
    wires: u32,
}

impl Lab {
    fn new(root: &Path) -> Result<Self, String> {
        let dir = match std::env::var_os("COREROUTER_VM_DIR") {
            Some(d) => PathBuf::from(d),
            None => {
                // Every worktree shares the main checkout's `vm/`.
                let common = output(Command::new("git").current_dir(root).args([
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-common-dir",
                ]))?;
                let common = PathBuf::from(common.trim());
                common
                    .parent()
                    .ok_or_else(|| format!("git common dir {} has no parent", common.display()))?
                    .join("vm")
            }
        };
        Ok(Self {
            root: root.to_path_buf(),
            dir,
        })
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// `/srv/lab/<worktree name>` inside the VM: one per worktree, so
    /// sessions never overwrite each other's sources or build caches.
    fn remote_dir(&self) -> Result<String, String> {
        let name = self
            .root
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .ok_or_else(|| "worktree path has no name".to_owned())?;
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
        {
            return Err(format!(
                "worktree name {name:?} is not a safe directory name"
            ));
        }
        Ok(format!("{LAB_ROOT}/{name}"))
    }

    // ---- create -------------------------------------------------------

    fn create(&self, args: &[String]) -> Result<(), String> {
        let spec = parse_spec(args)?;
        if self.state()?.is_some() {
            return Err(format!(
                "{NAME} already exists: `cargo xtask vm-lab destroy` first (or `reset`)"
            ));
        }
        let started = Instant::now();
        std::fs::create_dir_all(self.path("base"))
            .map_err(|e| format!("{}: {e}", self.dir.display()))?;
        let base = self.image()?;
        self.keys()?;
        self.seed(&spec)?;
        let overlay = self.path(&format!("{NAME}.qcow2"));
        let _ = std::fs::remove_file(&overlay);
        run_ok(Command::new("qemu-img").args([
            "create",
            "-q",
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            "-b",
            &base.to_string_lossy(),
            &overlay.to_string_lossy(),
            &format!("{}G", spec.disk_gib),
        ]))?;
        let xml = self.path(&format!("{NAME}.xml"));
        std::fs::write(&xml, self.domain_xml(&spec, &overlay))
            .map_err(|e| format!("{}: {e}", xml.display()))?;
        virsh(&["define", &xml.to_string_lossy()])?;
        virsh(&["start", NAME])?;
        eprintln!("vm-lab: {NAME} defined and started; waiting for cloud-init (packages)…");
        self.wait_ssh(Duration::from_secs(600))?;
        // `status --wait` exits 2 for "done with recoverable errors" (a
        // deprecation warning is enough): the long form says what it was.
        let status =
            self.ssh_output("cloud-init status --wait >/dev/null; cloud-init status --long; true")?;
        eprintln!("{}", status.trim());
        if !status.contains("status: done") {
            return Err(format!("cloud-init did not finish:\n{status}"));
        }
        // Boot into the kernel cloud-init installed.
        if self
            .ssh_output("test -e /var/run/reboot-required && echo yes; true")?
            .contains("yes")
        {
            eprintln!("vm-lab: rebooting into the new kernel…");
            self.down()?;
            self.up()?;
        }
        eprintln!("vm-lab: kernel {}", self.ssh_output("uname -r")?.trim());
        self.provision()?;
        // The seed has done its job; an empty CD-ROM keeps snapshots internal
        // (qcow2 only) and stops cloud-init from looking at it again.
        virsh(&["change-media", NAME, "sda", "--eject", "--config"])?;
        self.snapshot("clean")?;
        eprintln!(
            "vm-lab: {NAME} ready in {:.0} s ({} vCPUs, {} MiB, {} wire(s)); `cargo xtask vm-lab status`",
            started.elapsed().as_secs_f64(),
            spec.cpus,
            spec.memory_mib,
            spec.wires
        );
        Ok(())
    }

    /// The cloud image, downloaded once and checked against the published
    /// SHA256SUMS; a mismatch is refused (and the file removed).
    fn image(&self) -> Result<PathBuf, String> {
        let base = self.path("base");
        let sums = base.join("SHA256SUMS");
        let img = base.join(IMAGE);
        let part = base.join(format!("{IMAGE}.part"));
        if !sums.exists() {
            download(&format!("{IMAGE_URL}SHA256SUMS"), &sums)?;
        }
        let text =
            std::fs::read_to_string(&sums).map_err(|e| format!("{}: {e}", sums.display()))?;
        let want = text
            .lines()
            .find_map(|l| {
                let (hash, file) = l.split_once(' ')?;
                (file.trim_start_matches([' ', '*']) == IMAGE).then(|| hash.to_ascii_lowercase())
            })
            .ok_or_else(|| format!("{IMAGE} is not listed in {}", sums.display()))?;
        if img.exists() {
            if sha256_file(&img)? == want {
                return Ok(img);
            }
            return Err(format!(
                "{} does not match SHA256SUMS ({want}); remove vm/base/ to download again",
                img.display()
            ));
        }
        if !part.exists() {
            eprintln!("vm-lab: downloading {IMAGE} (~600 MB)…");
            download(&format!("{IMAGE_URL}{IMAGE}"), &part)?;
        }
        let have = sha256_file(&part)?;
        if have != want {
            let _ = std::fs::remove_file(&part);
            return Err(format!(
                "checksum mismatch for {IMAGE}: got {have}, SHA256SUMS says {want}; file removed"
            ));
        }
        eprintln!("vm-lab: {IMAGE} sha256 {have} ok");
        std::fs::rename(&part, &img).map_err(|e| format!("{}: {e}", img.display()))?;
        Ok(img)
    }

    /// The lab's own client key and the VM's host key (pinned in
    /// `known_hosts` under the alias `corerouter-lab`, so a new address
    /// from DHCP never asks to trust anything).
    fn keys(&self) -> Result<(), String> {
        for key in ["id_ed25519", "ssh_host_ed25519_key"] {
            let p = self.path(key);
            if !p.exists() {
                run_ok(Command::new("ssh-keygen").args([
                    "-q",
                    "-t",
                    "ed25519",
                    "-N",
                    "",
                    "-C",
                    &format!("{NAME}-{key}"),
                    "-f",
                    &p.to_string_lossy(),
                ]))?;
            }
        }
        let host_pub = read(&self.path("ssh_host_ed25519_key.pub"))?;
        let mut fields = host_pub.split_whitespace();
        let (Some(kind), Some(key)) = (fields.next(), fields.next()) else {
            return Err("ssh_host_ed25519_key.pub is malformed".into());
        };
        write(&self.path("known_hosts"), &format!("{NAME} {kind} {key}\n"))
    }

    fn seed(&self, spec: &Spec) -> Result<(), String> {
        let seed = self.path("seed");
        std::fs::create_dir_all(&seed).map_err(|e| format!("{}: {e}", seed.display()))?;
        let client = read(&self.path("id_ed25519.pub"))?;
        let host_key = read(&self.path("ssh_host_ed25519_key"))?;
        let host_pub = read(&self.path("ssh_host_ed25519_key.pub"))?;
        let indented: String = host_key.lines().map(|l| format!("    {l}\n")).collect();
        let packages: String = PACKAGES.iter().map(|p| format!("  - {p}\n")).collect();
        let user_data = format!(
            "#cloud-config\n\
             hostname: {NAME}\n\
             users:\n\
             \x20 - name: {USER}\n\
             \x20   shell: /bin/bash\n\
             \x20   sudo: \"ALL=(ALL) NOPASSWD:ALL\"\n\
             \x20   lock_passwd: true\n\
             \x20   ssh_authorized_keys:\n\
             \x20     - {client}\n\
             ssh_pwauth: false\n\
             disable_root: true\n\
             ssh_deletekeys: true\n\
             ssh_genkeytypes: [ed25519]\n\
             ssh_keys:\n\
             \x20 ed25519_private: |\n{indented}\
             \x20 ed25519_public: {host_pub}\n\
             package_update: true\n\
             packages:\n{packages}\
             runcmd:\n\
             \x20 - [systemctl, disable, --now, unattended-upgrades.service, apt-daily.timer, apt-daily-upgrade.timer]\n\
             \x20 - [mkdir, -p, {LAB_ROOT}]\n",
            client = client.trim(),
            host_pub = host_pub.trim(),
        );
        let instance = format!("{NAME}-{}", unix_now());
        let meta = format!("instance-id: {instance}\nlocal-hostname: {NAME}\n");
        let mut net = format!(
            "version: 2\nethernets:\n  mgmt0:\n    match:\n      macaddress: \"{MGMT_MAC}\"\n    \
             set-name: mgmt0\n    dhcp4: true\n    dhcp6: false\n    dhcp-identifier: mac\n"
        );
        for (name, mac) in wire_nics(spec.wires) {
            net.push_str(&format!(
                "  {name}:\n    match:\n      macaddress: \"{mac}\"\n    set-name: {name}\n    \
                 dhcp4: false\n    dhcp6: false\n    accept-ra: false\n    link-local: []\n    \
                 optional: true\n"
            ));
        }
        write(&seed.join("user-data"), &user_data)?;
        write(&seed.join("meta-data"), &meta)?;
        write(&seed.join("network-config"), &net)?;
        let iso = self.path("seed.iso");
        let _ = std::fs::remove_file(&iso);
        run_ok(
            Command::new("genisoimage")
                .args(["-quiet", "-output", &iso.to_string_lossy()])
                .args(["-volid", "cidata", "-joliet", "-rock"])
                .arg(seed.join("user-data"))
                .arg(seed.join("meta-data"))
                .arg(seed.join("network-config")),
        )
    }

    fn domain_xml(&self, spec: &Spec, overlay: &Path) -> String {
        let mut nics = format!(
            "    <interface type='network'>\n      <source network='default'/>\n      \
             <mac address='{MGMT_MAC}'/>\n      <model type='virtio'/>\n    </interface>\n"
        );
        for (i, (_, mac)) in wire_nics(spec.wires).into_iter().enumerate() {
            // NIC 2k sends to the port NIC 2k+1 listens on, and back.
            let pair = u16::try_from(i / 2).unwrap_or(0);
            let (local, remote) = if i % 2 == 0 {
                (WIRE_PORT_BASE + 2 * pair, WIRE_PORT_BASE + 2 * pair + 1)
            } else {
                (WIRE_PORT_BASE + 2 * pair + 1, WIRE_PORT_BASE + 2 * pair)
            };
            nics.push_str(&format!(
                "    <interface type='udp'>\n      <mac address='{mac}'/>\n      \
                 <source address='127.0.0.1' port='{remote}'>\n        \
                 <local address='127.0.0.1' port='{local}'/>\n      </source>\n      \
                 <model type='virtio'/>\n    </interface>\n"
            ));
        }
        format!(
            "<domain type='kvm'>\n  <name>{NAME}</name>\n  \
             <description>CoreRouter VM lab (cargo xtask vm-lab, docs/vm-lab.md)</description>\n  \
             <memory unit='MiB'>{mem}</memory>\n  <vcpu>{cpus}</vcpu>\n  \
             <os><type arch='x86_64' machine='q35'>hvm</type><boot dev='hd'/></os>\n  \
             <features><acpi/><apic/></features>\n  \
             <cpu mode='host-passthrough' check='none' migratable='off'/>\n  \
             <clock offset='utc'/>\n  <on_poweroff>destroy</on_poweroff>\n  \
             <on_reboot>restart</on_reboot>\n  <on_crash>destroy</on_crash>\n  <devices>\n    \
             <disk type='file' device='disk'>\n      \
             <driver name='qemu' type='qcow2' discard='unmap'/>\n      \
             <source file='{overlay}'/>\n      <target dev='vda' bus='virtio'/>\n    </disk>\n    \
             <disk type='file' device='cdrom'>\n      <driver name='qemu' type='raw'/>\n      \
             <source file='{seed}'/>\n      <target dev='sda' bus='sata'/>\n      <readonly/>\n    \
             </disk>\n{nics}    <serial type='pty'/>\n    <console type='pty'/>\n    \
             <channel type='unix'><target type='virtio' name='org.qemu.guest_agent.0'/></channel>\n    \
             <rng model='virtio'><backend model='random'>/dev/urandom</backend></rng>\n  \
             </devices>\n</domain>\n",
            mem = spec.memory_mib,
            cpus = spec.cpus,
            overlay = overlay.display(),
            seed = self.path("seed.iso").display(),
        )
    }

    /// rustup + the stable toolchain for root, in /opt/rust (the
    /// `rust-toolchain.toml` components come on the first `cargo`).
    fn provision(&self) -> Result<(), String> {
        let script = format!(
            "set -e\n\
             if [ ! -x /opt/rust/cargo/bin/cargo ]; then\n\
             \x20 export RUSTUP_HOME=/opt/rust/rustup CARGO_HOME=/opt/rust/cargo\n\
             \x20 curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
             | sh -s -- -y -q --profile minimal --default-toolchain stable --no-modify-path >/dev/null\n\
             \x20 printf 'export RUSTUP_HOME=/opt/rust/rustup CARGO_HOME=/opt/rust/cargo\\n\
             export PATH=/opt/rust/cargo/bin:$PATH\\n' > {RUST_ENV}\n\
             fi\n\
             mkdir -p {LAB_ROOT}\n\
             . {RUST_ENV} && cargo --version\n"
        );
        self.ssh_root_script(&script)
    }

    // ---- lifecycle ----------------------------------------------------

    /// `Some("running")`, `Some("shut off")`… or `None` when not defined.
    fn state(&self) -> Result<Option<String>, String> {
        let out = Command::new("virsh")
            .args(["-c", URI, "domstate", NAME])
            .output()
            .map_err(|e| format!("virsh: {e}"))?;
        if out.status.success() {
            return Ok(Some(String::from_utf8_lossy(&out.stdout).trim().to_owned()));
        }
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("failed to get domain") || err.contains("Domain not found") {
            return Ok(None);
        }
        Err(format!("virsh domstate: {}", err.trim()))
    }

    fn require(&self) -> Result<String, String> {
        self.state()?
            .ok_or_else(|| format!("{NAME} does not exist: `cargo xtask vm-lab create`"))
    }

    fn up(&self) -> Result<(), String> {
        if self.require()? != "running" {
            virsh(&["start", NAME])?;
        }
        self.wait_ssh(Duration::from_secs(180))
    }

    fn down(&self) -> Result<(), String> {
        if self.require()? != "running" {
            return Ok(());
        }
        self.close_master();
        virsh(&["shutdown", NAME])?;
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            if self.state()?.as_deref() != Some("running") {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        eprintln!("vm-lab: no clean shutdown in 90 s; powering off");
        virsh(&["destroy", NAME]).map(|_| ())
    }

    fn destroy(&self) -> Result<(), String> {
        if let Some(state) = self.state()? {
            self.close_master();
            if state == "running" {
                let _ = virsh(&["destroy", NAME]);
            }
            virsh(&["undefine", NAME, "--snapshots-metadata"])?;
        }
        for f in [
            format!("{NAME}.qcow2"),
            "seed.iso".into(),
            format!("{NAME}.xml"),
        ] {
            let _ = std::fs::remove_file(self.path(&f));
        }
        eprintln!("vm-lab: {NAME} destroyed (vm/base/ cache and the lab key stay)");
        Ok(())
    }

    fn snapshot(&self, name: &str) -> Result<(), String> {
        check_snapshot_name(name)?;
        let was_running = self.require()? == "running";
        // Offline: an internal disk snapshot, no RAM image (8 GB) to store.
        self.down()?;
        if virsh(&["snapshot-list", NAME, "--name"])?
            .lines()
            .any(|l| l.trim() == name)
        {
            virsh(&["snapshot-delete", NAME, name])?;
        }
        virsh(&["snapshot-create-as", NAME, name, "--atomic"])?;
        eprintln!("vm-lab: snapshot `{name}` taken");
        if was_running { self.up() } else { Ok(()) }
    }

    fn reset(&self, name: &str) -> Result<(), String> {
        check_snapshot_name(name)?;
        let started = Instant::now();
        if self.require()? == "running" {
            self.close_master();
            virsh(&["destroy", NAME])?;
        }
        virsh(&["snapshot-revert", NAME, name])?;
        self.up()?;
        eprintln!(
            "vm-lab: back to `{name}` and booted in {:.1} s",
            started.elapsed().as_secs_f64()
        );
        Ok(())
    }

    fn status(&self) -> Result<(), String> {
        let Some(state) = self.state()? else {
            println!(
                "{NAME}: not created (`cargo xtask vm-lab create`); cache in {}",
                self.dir.display()
            );
            return Ok(());
        };
        println!("{NAME}: {state}");
        if state == "running" {
            match self.address() {
                Ok(Some(ip)) => println!(
                    "address: {ip} (user {USER}, key {})",
                    self.path("id_ed25519").display()
                ),
                Ok(None) => println!("address: none yet"),
                Err(e) => println!("address: {e}"),
            }
        }
        let snaps = virsh(&["snapshot-list", NAME, "--name"])?;
        let snaps: Vec<&str> = snaps
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        println!(
            "snapshots: {}",
            if snaps.is_empty() {
                "none".into()
            } else {
                snaps.join(", ")
            }
        );
        let overlay = self.path(&format!("{NAME}.qcow2"));
        if let Ok(info) =
            output(Command::new("qemu-img").args(["info", "-U", &overlay.to_string_lossy()]))
        {
            for l in info
                .lines()
                .filter(|l| l.starts_with("virtual size") || l.starts_with("disk size"))
            {
                println!("{l}");
            }
        }
        if state == "running" && self.ssh_output("true").is_ok() {
            let info = self.ssh_output(
                "nproc; free -m | awk '/Mem:/{print $2\" MiB RAM\"}'; ip -br link | grep -v '^lo'; \
                 df -h / | tail -1 | awk '{print $3\" used of \"$2\" on /\"}'",
            )?;
            print!("{info}");
        }
        Ok(())
    }

    // ---- ssh ----------------------------------------------------------

    /// The VM's IPv4 on the `default` network, from libvirt's DHCP leases.
    fn address(&self) -> Result<Option<String>, String> {
        // The guest agent knows the address in use; the lease table may
        // also hold an older lease of the same NIC (a continuation row).
        if let Ok(out) = virsh(&["domifaddr", NAME, "--source", "agent"])
            && let Some(ip) = mgmt_ipv4(&out)
        {
            return Ok(Some(ip));
        }
        Ok(mgmt_ipv4(&virsh(&[
            "domifaddr",
            NAME,
            "--source",
            "lease",
        ])?))
    }

    fn ssh_base(&self, ip: &str) -> Command {
        let mut c = Command::new("ssh");
        c.args(["-F", "/dev/null", "-i"])
            .arg(self.path("id_ed25519"))
            .arg("-o")
            .arg(format!(
                "UserKnownHostsFile={}",
                self.path("known_hosts").display()
            ))
            .args([
                "-o",
                &format!("HostKeyAlias={NAME}"),
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "ServerAliveInterval=15",
                "-o",
                "LogLevel=ERROR",
                "-o",
                "ControlMaster=auto",
                "-o",
                "ControlPersist=300",
            ])
            .arg("-o")
            .arg(format!("ControlPath={}/cm-%C", self.dir.display()))
            .arg(format!("{USER}@{ip}"));
        c
    }

    fn ssh(&self) -> Result<Command, String> {
        let ip = self
            .address()?
            .ok_or_else(|| format!("{NAME} has no address yet: `cargo xtask vm-lab up`"))?;
        Ok(self.ssh_base(&ip))
    }

    fn close_master(&self) {
        if let Ok(Some(ip)) = self.address() {
            let _ = self
                .ssh_base(&ip)
                .args(["-O", "exit"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }

    fn wait_ssh(&self, limit: Duration) -> Result<(), String> {
        let deadline = Instant::now() + limit;
        loop {
            if let Some(ip) = self.address()? {
                let ok = self
                    .ssh_base(&ip)
                    .arg("true")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|s| s.success());
                if ok {
                    return Ok(());
                }
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "{NAME} not reachable by SSH after {} s (`virsh -c {URI} console {NAME}`)",
                    limit.as_secs()
                ));
            }
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    fn ssh_output(&self, cmd: &str) -> Result<String, String> {
        output(self.ssh()?.arg(cmd))
    }

    /// A bash script as root, output streamed.
    fn ssh_root_script(&self, script: &str) -> Result<(), String> {
        let mut child = self
            .ssh()?
            .args(["sudo", "bash", "-s"])
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| format!("ssh: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
            use std::io::Write;
            stdin
                .write_all(script.as_bytes())
                .map_err(|e| format!("ssh stdin: {e}"))?;
        }
        let status = child.wait().map_err(|e| format!("ssh: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("command in {NAME} failed: {status}"))
        }
    }

    fn ssh_interactive(&self, args: &[String]) -> Result<(), String> {
        self.up()?;
        let mut c = self.ssh()?;
        if args.is_empty() {
            c.arg("-t");
        } else {
            c.arg(remote_command(args));
        }
        let status = c.status().map_err(|e| format!("ssh: {e}"))?;
        exit_like(status)
    }

    // ---- sync / run ---------------------------------------------------

    /// `rsync -e <our ssh>` writing as root into `dest` in the VM.
    fn rsync(&self, dest: &str) -> Result<(Command, String), String> {
        // rsync wants the ssh command as one string; paths are quoted.
        let mut ssh_cmd: Vec<String> = self
            .ssh()?
            .get_args()
            .map(|a| shell_quote(&a.to_string_lossy()))
            .collect();
        let target = ssh_cmd
            .pop()
            .ok_or_else(|| "ssh has no target".to_owned())?;
        ssh_cmd.insert(0, "ssh".into());
        let mut c = Command::new("rsync");
        c.arg("-e")
            .arg(ssh_cmd.join(" "))
            .arg(format!("--rsync-path=sudo mkdir -p {dest} && sudo rsync"));
        Ok((c, format!("{target}:{dest}")))
    }

    fn sync(&self) -> Result<(), String> {
        let started = Instant::now();
        let dest = format!("{}/src/", self.remote_dir()?);
        let (mut rsync, to) = self.rsync(&dest)?;
        run_ok(
            rsync
                .args(["-a", "--delete", "--info=stats0"])
                .args(["--exclude=/target", "--exclude=/target-*", "--exclude=/vm/"])
                .args([
                    "--exclude=/.git",
                    "--exclude=/plan/",
                    "--exclude=/fuzz/target/",
                ])
                .args(["--exclude=/apps/corerouter-gui/dist/", "--exclude=/dist/"])
                .arg(format!("{}/", self.root.display()))
                .arg(to),
        )?;
        eprintln!(
            "vm-lab: synced {} → {NAME}:{dest} in {:.1} s",
            self.root.display(),
            started.elapsed().as_secs_f64()
        );
        Ok(())
    }

    /// Files from the host (a `.deb`, a capture) into `/srv/lab/inbox/`.
    fn put(&self, files: &[String]) -> Result<(), String> {
        if files.is_empty() {
            return Err(format!("nothing to copy\n{HELP}"));
        }
        self.up()?;
        let dest = format!("{LAB_ROOT}/inbox/");
        let (mut rsync, to) = self.rsync(&dest)?;
        run_ok(rsync.arg("-t").args(files).arg(to))?;
        eprintln!("vm-lab: copied {} file(s) to {NAME}:{dest}", files.len());
        Ok(())
    }

    fn run(&self, args: &[String]) -> Result<(), String> {
        let mut sync = true;
        let mut rest = args;
        while let Some((first, tail)) = rest.split_first() {
            match first.as_str() {
                "--no-sync" => sync = false,
                "--" => {
                    rest = tail;
                    break;
                }
                _ => break,
            }
            rest = tail;
        }
        if rest.is_empty() {
            return Err(format!("nothing to run\n{HELP}"));
        }
        let started = Instant::now();
        self.up()?;
        if sync {
            self.sync()?;
        }
        let dir = self.remote_dir()?;
        let script = format!(
            "if [ ! -r {RUST_ENV} ]; then echo 'vm-lab: no Rust toolchain in the VM; run `cargo xtask vm-lab create`' >&2; exit 1; fi\n\
             . {RUST_ENV}\n\
             export CARGO_TARGET_DIR={dir}/target CARGO_TERM_COLOR=${{CARGO_TERM_COLOR:-always}}\n\
             cd {dir}/src && {cmd}\n",
            cmd = remote_command(rest)
        );
        // `bash -c` (not a heredoc on stdin), so the command keeps a
        // terminal-less stdin of its own and `-t` is not needed.
        let status = self
            .ssh()?
            .args(["sudo", "bash", "-c"])
            .arg(shell_quote(&script))
            .stdin(Stdio::null())
            .status()
            .map_err(|e| format!("ssh: {e}"))?;
        eprintln!(
            "vm-lab: round (sync + command) {:.1} s, {status}",
            started.elapsed().as_secs_f64()
        );
        exit_like(status)
    }
}

fn parse_spec(args: &[String]) -> Result<Spec, String> {
    let mut spec = Spec {
        cpus: 8,
        memory_mib: 8192,
        disk_gib: 20,
        wires: 1,
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| format!("{flag} needs a value"))?
            .parse::<u32>()
            .map_err(|e| format!("{flag}: {e}"))?;
        let (slot, lo, hi) = match flag.as_str() {
            "--cpus" => (&mut spec.cpus, 1, 64),
            "--memory" => (&mut spec.memory_mib, 1024, 65_536),
            "--disk" => (&mut spec.disk_gib, 10, 200),
            "--wires" => (&mut spec.wires, 0, MAX_WIRES),
            other => return Err(format!("unknown option {other}\n{HELP}")),
        };
        if !(lo..=hi).contains(&value) {
            return Err(format!("{flag} {value}: must be {lo}..={hi}"));
        }
        *slot = value;
    }
    Ok(spec)
}

/// `(wire0a, mac), (wire0b, mac), …` for `wires` pairs.
fn wire_nics(wires: u32) -> Vec<(String, String)> {
    (0..wires)
        .flat_map(|w| {
            [("a", 0), ("b", 1)].map(|(side, n)| {
                (
                    format!("wire{w}{side}"),
                    format!("52:54:00:c0:73:{:02x}", w * 2 + n),
                )
            })
        })
        .collect()
}

/// The last IPv4 of the management NIC in a `virsh domifaddr` table, where
/// a row whose name is `-` continues the NIC above it.
fn mgmt_ipv4(table: &str) -> Option<String> {
    let mut mac = "";
    let mut found = None;
    for line in table.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        let [name, m, proto, addr] = cols.as_slice() else {
            continue;
        };
        if *name != "-" {
            mac = m;
        }
        if mac.eq_ignore_ascii_case(MGMT_MAC) && *proto == "ipv4" {
            found = addr.split('/').next().map(str::to_owned);
        }
    }
    found
}

fn check_snapshot_name(name: &str) -> Result<(), String> {
    if !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_".contains(c))
    {
        Ok(())
    } else {
        Err(format!(
            "snapshot name {name:?}: letters, digits, - and _ only"
        ))
    }
}

/// One argument is taken as a shell line (`run -- 'a && b'`); several are
/// quoted one by one (`run -- cargo test -p x`).
fn remote_command(args: &[String]) -> String {
    match args {
        [one] => one.clone(),
        many => many
            .iter()
            .map(|a| shell_quote(a))
            .collect::<Vec<_>>()
            .join(" "),
    }
}

fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./=:,@%+".contains(c))
    {
        s.to_owned()
    } else {
        format!("'{}'", s.replace('\'', "'\\''"))
    }
}

fn exit_like(status: std::process::ExitStatus) -> Result<(), String> {
    if status.success() {
        Ok(())
    } else {
        Err(format!("command in {NAME} exited with {status}"))
    }
}

fn virsh(args: &[&str]) -> Result<String, String> {
    output(Command::new("virsh").args(["-c", URI]).args(args))
}

fn output(cmd: &mut Command) -> Result<String, String> {
    let out = cmd
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("{:?}: {e}", cmd.get_program()))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        Err(format!(
            "{} {}: {}",
            cmd.get_program().to_string_lossy(),
            cmd.get_args()
                .map(|a| a.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

fn run_ok(cmd: &mut Command) -> Result<(), String> {
    output(cmd).map(|_| ())
}

fn download(url: &str, to: &Path) -> Result<(), String> {
    let status = Command::new("curl")
        .args(["-fSL", "--progress-bar", "--proto", "=https", "-o"])
        .arg(to)
        .arg(url)
        .status()
        .map_err(|e| format!("curl: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        let _ = std::fs::remove_file(to);
        Err(format!("download of {url} failed: {status}"))
    }
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut f = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f
            .read(&mut buf)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        match buf.get(..n) {
            Some(chunk) if n > 0 => hasher.update(chunk),
            _ => break,
        }
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn write(path: &Path, text: &str) -> Result<(), String> {
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wires_pair_up_and_never_reuse_a_mac() {
        let nics = wire_nics(2);
        let names: Vec<&str> = nics.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["wire0a", "wire0b", "wire1a", "wire1b"]);
        let mut macs: Vec<&str> = nics.iter().map(|(_, m)| m.as_str()).collect();
        macs.push(MGMT_MAC);
        let before = macs.len();
        macs.sort_unstable();
        macs.dedup();
        assert_eq!(macs.len(), before);
    }

    #[test]
    fn wire_ends_point_at_each_other() {
        let lab = Lab {
            root: "/w/x".into(),
            dir: "/c/vm".into(),
        };
        let spec = parse_spec(&[]).unwrap();
        let xml = lab.domain_xml(&Spec { wires: 1, ..spec }, Path::new("/c/vm/o.qcow2"));
        assert!(xml.contains("port='47211'>\n        <local address='127.0.0.1' port='47210'/>"));
        assert!(xml.contains("port='47210'>\n        <local address='127.0.0.1' port='47211'/>"));
        assert!(xml.contains(&format!("<name>{NAME}</name>")));
    }

    #[test]
    fn address_comes_from_the_management_nic_rows() {
        let table = " Name       MAC address          Protocol     Address
-------------------------------------------------------------------------------
 lo         00:00:00:00:00:00    ipv4         127.0.0.1/8
 vnet4      52:54:00:c0:72:01    ipv4         192.168.122.46/24
 -          -                    ipv4         192.168.122.47/24
 wire0a     52:54:00:c0:73:00    ipv4         10.0.0.1/24
";
        assert_eq!(mgmt_ipv4(table).as_deref(), Some("192.168.122.47"));
        assert_eq!(mgmt_ipv4(" Name MAC Protocol Address\n"), None);
    }

    #[test]
    fn spec_flags_are_checked() {
        let s = parse_spec(&["--cpus".into(), "16".into(), "--wires".into(), "2".into()]).unwrap();
        assert_eq!((s.cpus, s.wires, s.memory_mib), (16, 2, 8192));
        assert!(parse_spec(&["--wires".into(), "9".into()]).is_err());
        assert!(parse_spec(&["--cpus".into()]).is_err());
        assert!(parse_spec(&["--bogus".into(), "1".into()]).is_err());
    }

    #[test]
    fn commands_are_quoted_for_the_remote_shell() {
        assert_eq!(
            remote_command(&["cargo xtask xdp-root".into()]),
            "cargo xtask xdp-root"
        );
        assert_eq!(
            remote_command(&["env".into(), "A=1".into(), "it's".into()]),
            "env A=1 'it'\\''s'"
        );
        assert!(check_snapshot_name("clean").is_ok());
        assert!(check_snapshot_name("a b").is_err());
        assert!(check_snapshot_name("../x").is_err());
    }
}

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
use crate::vm_tools::{self, Source, TOOLS};

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
/// Extra kernel command line in the guest (see `guest_settings`).
const GRUB_CFG: &str = "/etc/default/grub.d/90-corerouter-lab.cfg";
const GUEST_CMDLINE: &str = "spec_rstack_overflow=off";
/// Held (flock) by each exclusive `run` inside the VM; `<LOCK>.owner` says
/// whose round it is (`key=value` lines, see `Owner`).
const LOCK: &str = "/run/corerouter-lab.lock";
/// Every process of a round carries it in its environment (`<host pid>.<start
/// time>` of the `vm-lab run` on the host): how leftovers are found and told
/// apart from a live round.
const ROUND_VAR: &str = "COREROUTER_LAB_ROUND";
/// How long `run` waits for the lock (`--lock-timeout`, or this variable).
const LOCK_TIMEOUT_VAR: &str = "COREROUTER_VM_LOCK_TIMEOUT";
const LOCK_TIMEOUT_DEFAULT: u64 = 30 * 60;
/// Held on the host by a round the user runs by hand
/// (`flock vm/root.lock cargo xtask vm-lab run …`): no snapshot or reset then.
const HOST_LOCK: &str = "root.lock";
/// Snapshot with the third-party tools in (`tools`); `reset` prefers it.
const TOOLS_SNAPSHOT: &str = "tools";
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
                    (defaults: 8 vCPUs, 16384 MiB, 20 GiB thin, 1 wire = 2 test NICs)
  up | down         start (and wait for SSH) | shut down
  ssh [cmd...]      shell (or one command) as user `lab`; `sudo` works inside
  sync              rsync this worktree to /srv/lab/<worktree>/src (no target*, .git)
  put <file...>     copy host files into /srv/lab/inbox/ (a .deb, a capture)
  status            state, address, who holds the VM lock and for how long
  run [--no-sync] [--shared] [--lock-timeout 30m] -- <cmd...>
                    health check (reset to `clean` if the VM is broken), sync, then run
                    <cmd> as root in /srv/lab/<worktree>/src with
                    CARGO_TARGET_DIR=/srv/lab/<worktree>/target (kept: incremental);
                    one run at a time unless --shared (builds only, no namespaces).
                    Waits for the lock up to --lock-timeout (or $COREROUTER_VM_LOCK_TIMEOUT;
                    default 30m; s/m/h), then fails showing who holds it. Warns about
                    processes the command left running
  unlock [--force]  show who holds the VM lock (owner, age, processes); with --force,
                    end what is left of rounds whose `vm-lab run` is gone, freeing the lock
  tools [--check]   install the third-party tools declared in xtask/src/vm_tools.rs
                    (official URL + SHA-256), then snapshot `tools`; --check only
                    says what is missing. Installing is the user's, once per tool
  snapshot [name] [--force]
                    save the disk (default `tools`, else `clean`; the VM is shut down
                    for it); refused while a round holds a lock, unless --force
  reset [name] [--force]
                    throw the disk back to a snapshot (default `tools`, else `clean`)
                    and boot; same lock rule
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
        "unlock" => lab.unlock(rest),
        "tools" => lab.tools(rest),
        "snapshot" | "reset" => {
            let force = rest.iter().any(|a| a == "--force");
            let named = rest.iter().find(|a| !a.starts_with("--")).cloned();
            let name = match named {
                Some(n) => Ok(n),
                None if sub == "reset" => lab.base_snapshot().map(str::to_owned),
                None => Ok(TOOLS_SNAPSHOT.to_owned()),
            };
            name.and_then(|n| {
                if !force {
                    lab.idle()?;
                }
                if sub == "reset" {
                    lab.reset(&n)
                } else {
                    lab.snapshot(&n)
                }
            })
        }
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
        let base = cloud_image(&self.path("base"))?;
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
        // Boot into the kernel cloud-init installed, with the lab's
        // command line.
        let settings = self.guest_settings()?;
        if settings
            || self
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
        // `host-model`, not `host-passthrough`: passthrough hands the guest
        // the host's CET shadow stack (KVM on kernel 7.0 offers it), which
        // QEMU 8.2 does not manage; after a while every process in the VM
        // segfaulted at the same shadow-stack address (**measured**,
        // 2026-10-25).
        format!(
            "<domain type='kvm'>\n  <name>{NAME}</name>\n  \
             <description>CoreRouter VM lab (cargo xtask vm-lab, docs/vm-lab.md)</description>\n  \
             <memory unit='MiB'>{mem}</memory>\n  <vcpu>{cpus}</vcpu>\n  \
             <os><type arch='x86_64' machine='q35'>hvm</type><boot dev='hd'/></os>\n  \
             <features><acpi/><apic/></features>\n  \
             <cpu mode='host-model' check='partial'/>\n  \
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
        self.wait_ssh(Duration::from_secs(180))?;
        // A `reset` to an older snapshot may predate a guest setting.
        if self.guest_settings()? {
            eprintln!("vm-lab: guest boot settings applied; rebooting");
            self.down()?;
            virsh(&["start", NAME])?;
            self.wait_ssh(Duration::from_secs(180))?;
        }
        Ok(())
    }

    /// Kernel command line the lab needs, written once; `true` when it was
    /// just written (takes effect on the next boot).
    ///
    /// `spec_rstack_overflow=off`: `host-model` cannot tell the guest that
    /// the CPU is immune to SRSO from user space (libvirt 10.0 has no name
    /// for those CPUID bits), so the guest picked "Safe RET" on every
    /// kernel return and ran 3× slower (veth 558 against 1811 kpps,
    /// **measured**). The host kernel does not use Safe RET on this CPU
    /// either ("IBPB on VMEXIT only"), so this matches bare metal.
    fn guest_settings(&self) -> Result<bool, String> {
        let out = self.ssh_output(&format!(
            "if [ -f {GRUB_CFG} ]; then echo present; else \
             printf '%s\\n' '# cargo xtask vm-lab (docs/vm-lab.md)' \
             'GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_CMDLINE_LINUX_DEFAULT {GUEST_CMDLINE}\"' \
             | sudo tee {GRUB_CFG} >/dev/null && sudo update-grub 2>/dev/null && echo written; fi"
        ))?;
        if out.contains("present") {
            Ok(false)
        } else if out.contains("written") {
            Ok(true)
        } else {
            Err(format!("could not write {GRUB_CFG}: {}", out.trim()))
        }
    }

    fn down(&self) -> Result<(), String> {
        if self.require()? != "running" {
            return Ok(());
        }
        self.close_master();
        virsh(&["shutdown", NAME])?;
        let deadline = Instant::now() + Duration::from_secs(90);
        while Instant::now() < deadline {
            // "in shutdown" is not done yet: a snapshot taken then races
            // QEMU on its way out (**measured**).
            if self.state()?.as_deref() == Some("shut off") {
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
        // A revert also brings back the definition saved with the snapshot
        // (CPU, memory): keep the current one.
        let current = virsh(&["dumpxml", "--inactive", "--security-info", NAME])?;
        virsh(&["snapshot-revert", NAME, name])?;
        let xml = self.path(&format!("{NAME}.xml"));
        write(&xml, &current)?;
        virsh(&["define", &xml.to_string_lossy()])?;
        self.up()?;
        eprintln!(
            "vm-lab: back to `{name}` and booted in {:.1} s",
            started.elapsed().as_secs_f64()
        );
        Ok(())
    }

    /// `tools` when it exists, else `clean`.
    fn base_snapshot(&self) -> Result<&'static str, String> {
        let list = virsh(&["snapshot-list", NAME, "--name"])?;
        Ok(if list.lines().any(|l| l.trim() == TOOLS_SNAPSHOT) {
            TOOLS_SNAPSHOT
        } else {
            "clean"
        })
    }

    /// Nobody in a round: neither the user's host lock nor `run`'s lock in
    /// the VM is held. A snapshot or reset would cut that round off.
    fn idle(&self) -> Result<(), String> {
        let host = self.path(HOST_LOCK);
        let free = Command::new("flock")
            .args(["-n", "-E", "75"])
            .arg(&host)
            .arg("true")
            .status()
            .map_err(|e| format!("flock: {e}"))?;
        if free.code() == Some(75) && !held_by_ancestor(&host) {
            return Err(format!(
                "{} is held (a round the user runs by hand); try again when it ends, or --force",
                host.display()
            ));
        }
        if self.state()?.as_deref() == Some("running")
            && self.address()?.is_some()
            && let Ok(report) = self.lock_report()
            && report.busy
        {
            let alive = owner_alive(&report.owner);
            return Err(format!(
                "a `vm-lab run` holds the VM; try again when it ends, `cargo xtask vm-lab unlock` \
                 if it is gone, or --force\n{}",
                report.describe(alive, &round_alive).trim_end()
            ));
        }
        Ok(())
    }

    /// Before each `run`: root works, a handful of processes start, and
    /// there is room on the disk and in memory. Two tries, a few seconds
    /// apart, so one busy moment does not trigger a reset.
    fn healthy(&self) -> Result<(), String> {
        let check = format!(
            "sudo -n bash -c 'for i in 1 2 3 4 5; do /bin/true || exit 11; done; \
             disk=$(df --output=avail -k {LAB_ROOT} | tail -1); \
             mem=$(awk \"/MemAvailable/{{print \\$2}}\" /proc/meminfo); \
             [ \"$disk\" -gt 2097152 ] || {{ echo \"disk: $((disk / 1024)) MiB free\" >&2; exit 12; }}; \
             [ \"$mem\" -gt 1048576 ] || {{ echo \"memory: $((mem / 1024)) MiB available\" >&2; exit 13; }}'"
        );
        let mut last = String::new();
        for attempt in 0..2 {
            if attempt > 0 {
                std::thread::sleep(Duration::from_secs(3));
            }
            match self.ssh_output(&check) {
                Ok(_) => return Ok(()),
                Err(e) => last = e,
            }
        }
        Err(last)
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
        match self.idle() {
            Ok(()) => println!("rounds: none (snapshot/reset allowed)"),
            Err(why) => println!("rounds: busy: {why}"),
        }
        // Free lock, but a round left something running (an FRR daemon).
        if state == "running"
            && let Ok(report) = self.lock_report()
            && !report.busy
            && !report.procs.is_empty()
        {
            print!(
                "left by rounds (`cargo xtask vm-lab unlock`):\n{}",
                report.describe(owner_alive(&report.owner), &round_alive)
            );
        }
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
            && let Some(ip) = mgmt_ipv4(&out, MGMT_MAC)
        {
            return Ok(Some(ip));
        }
        Ok(mgmt_ipv4(
            &virsh(&["domifaddr", NAME, "--source", "lease"])?,
            MGMT_MAC,
        ))
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
                    // The app copies `.claude/` into each worktree, parked
                    // Buildroot trees included (4.2 GB, measured): never
                    // send it to the VM's 20 GiB disk.
                    "--exclude=/.claude/",
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

    /// The third-party tools of `vm_tools::TOOLS`: `--check` reports, the
    /// default installs what is missing and snapshots `tools`.
    fn tools(&self, args: &[String]) -> Result<(), String> {
        let check = match args {
            [] => false,
            [a] if a == "--check" => true,
            _ => return Err(format!("usage: cargo xtask vm-lab tools [--check]\n{HELP}")),
        };
        self.up()?;
        let missing = vm_tools::missing(TOOLS, &self.ssh_output(&vm_tools::query(TOOLS))?);
        let describe = |list: &[(&vm_tools::Tool, Option<String>)]| -> String {
            list.iter()
                .map(|(t, have)| match (t.version, have) {
                    ("", _) => t.package.to_owned(),
                    (v, Some(h)) => format!("{} {v} (has {h})", t.package),
                    (v, None) => format!("{} {v}", t.package),
                })
                .collect::<Vec<_>>()
                .join(", ")
        };
        if check {
            if missing.is_empty() {
                eprintln!("vm-lab: all {} tools present", TOOLS.len());
                return Ok(());
            }
            return Err(format!(
                "missing in {NAME}: {}. Installing third-party code is the user's call, once: \
                 ask them to run `cargo xtask vm-lab tools`",
                describe(&missing)
            ));
        }
        if !missing.is_empty() {
            eprintln!("vm-lab: installing {}", describe(&missing));
            self.install(&missing)?;
            let left = vm_tools::missing(TOOLS, &self.ssh_output(&vm_tools::query(TOOLS))?);
            if !left.is_empty() {
                return Err(format!("still missing after install: {}", describe(&left)));
            }
        }
        let installed = self.ssh_output(&vm_tools::query(TOOLS))?;
        for t in TOOLS {
            let version = installed
                .lines()
                .find_map(|l| l.strip_prefix(t.package)?.strip_prefix(" installed "))
                .unwrap_or("?");
            println!("{:<12} {:<28} {}", t.package, version, t.why);
        }
        if missing.is_empty() && self.base_snapshot()? == TOOLS_SNAPSHOT {
            eprintln!("vm-lab: nothing to do; snapshot `{TOOLS_SNAPSHOT}` exists");
            return Ok(());
        }
        match self.idle() {
            Ok(()) => self.snapshot(TOOLS_SNAPSHOT),
            Err(why) => Err(format!(
                "tools installed, but no snapshot yet: {why}. Then: cargo xtask vm-lab snapshot {TOOLS_SNAPSHOT}"
            )),
        }
    }

    /// Downloads each `.deb` once into `vm/tools/` (checked against its
    /// SHA-256 here and again in the VM), then one `apt-get install` for
    /// everything, so apt resolves the `.deb`s' dependencies.
    fn install(&self, list: &[(&vm_tools::Tool, Option<String>)]) -> Result<(), String> {
        let cache = self.path("tools");
        std::fs::create_dir_all(&cache).map_err(|e| format!("{}: {e}", cache.display()))?;
        let remote = format!("{LAB_ROOT}/tools/");
        let mut debs = Vec::new();
        let mut targets = Vec::new();
        let mut checks = Vec::new();
        for (t, _) in list {
            match (&t.source, t.file()) {
                (Source::Deb { url, sha256 }, Some(file)) => {
                    let local = cache.join(file);
                    if !local.exists() || sha256_file(&local)? != *sha256 {
                        let part = cache.join(format!("{file}.part"));
                        eprintln!("vm-lab: downloading {url}");
                        download(url, &part)?;
                        let have = sha256_file(&part)?;
                        if have != *sha256 {
                            let _ = std::fs::remove_file(&part);
                            return Err(format!(
                                "checksum mismatch for {file}: got {have}, xtask/src/vm_tools.rs says {sha256}; file removed"
                            ));
                        }
                        std::fs::rename(&part, &local)
                            .map_err(|e| format!("{}: {e}", local.display()))?;
                    }
                    eprintln!("vm-lab: {file} sha256 {sha256} ok");
                    debs.push(local.to_string_lossy().into_owned());
                    checks.push((sha256.to_string(), format!("{remote}{file}")));
                    targets.push(format!("{remote}{file}"));
                }
                _ => targets.push(t.package.to_owned()),
            }
        }
        if !debs.is_empty() {
            let (mut rsync, to) = self.rsync(&remote)?;
            run_ok(rsync.arg("-t").args(&debs).arg(to))?;
        }
        self.ssh_root_script(&vm_tools::install_script(&checks, &targets))
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
        let mut exclusive = true;
        let mut timeout = match std::env::var(LOCK_TIMEOUT_VAR) {
            Ok(v) => parse_duration(&v).map_err(|e| format!("${LOCK_TIMEOUT_VAR}: {e}"))?,
            Err(_) => LOCK_TIMEOUT_DEFAULT,
        };
        let mut rest = args;
        while let Some((first, tail)) = rest.split_first() {
            match first.as_str() {
                "--no-sync" => sync = false,
                "--shared" => exclusive = false,
                "--lock-timeout" => {
                    let (v, t) = tail
                        .split_first()
                        .ok_or_else(|| "--lock-timeout needs a value (30m, 900, 1h)".to_owned())?;
                    timeout = parse_duration(v).map_err(|e| format!("--lock-timeout: {e}"))?;
                    rest = t;
                    continue;
                }
                f if f.starts_with("--lock-timeout=") => {
                    let v = f.strip_prefix("--lock-timeout=").unwrap_or_default();
                    timeout = parse_duration(v).map_err(|e| format!("--lock-timeout: {e}"))?;
                }
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
        // Unreachable counts as unhealthy too (sshd was among the victims).
        if let Err(why) = self.up().and_then(|()| self.healthy()) {
            let base = self.base_snapshot()?;
            eprintln!("vm-lab: {NAME} is unhealthy ({why}); `reset` to `{base}`");
            self.reset(base)?;
            self.healthy()
                .map_err(|e| format!("{NAME} still unhealthy after reset: {e}"))?;
        }
        let dir = self.remote_dir()?;
        if sync {
            // The sync writes `<dir>/src` before the round waits for the
            // lock: a second round from this worktree would overwrite the
            // source of one still queued or running (seen 2026-10-30).
            let busy = self.ssh_output(&same_dir_rounds_check(&dir))?;
            let busy = busy.split_whitespace().collect::<Vec<_>>();
            if !busy.is_empty() {
                return Err(format!(
                    "a round from this worktree is already queued or running in the VM \
                     (pids {}): the sync would overwrite its source in {dir}/src; wait for it \
                     to end (`cargo xtask vm-lab status`), or pass --no-sync to reuse that source",
                    busy.join(" ")
                ));
            }
            self.sync()?;
        }
        let round = own_round();
        let script = format!(
            "if [ ! -r {RUST_ENV} ]; then echo 'vm-lab: no Rust toolchain in the VM; run `cargo xtask vm-lab create`' >&2; exit 1; fi\n\
             . {RUST_ENV}\n\
             export CARGO_TARGET_DIR={dir}/target CARGO_TERM_COLOR=${{CARGO_TERM_COLOR:-always}}\n\
             {body}",
            body = round_script(&Round {
                lock: LOCK,
                dir: &dir,
                cmd: &remote_command(rest),
                exclusive,
                timeout_s: timeout,
                id: &round,
                host_pid: std::process::id(),
            }),
        );
        // `bash -c` (not a heredoc on stdin), so the command keeps a
        // terminal-less stdin of its own and `-t` is not needed. `env` puts
        // the round mark in the environment every process of it inherits.
        let status = self
            .ssh()?
            .args(["sudo", "env", &format!("{ROUND_VAR}={round}"), "bash", "-c"])
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

    // ---- lock: status / unlock ----------------------------------------

    /// The lock as the VM sees it: busy or not, the owner file and every
    /// process that belongs to a round or has the lock file open.
    fn lock_report(&self) -> Result<LockReport, String> {
        let script = format!(
            "lock={LOCK}\n\
             if flock -n \"$lock\" true 2>/dev/null; then echo lock=free; else echo lock=busy; fi\n\
             echo \"now=$(date +%s)\"\n\
             echo --owner--\n\
             cat \"$lock.owner\" 2>/dev/null\n\
             echo --procs--\n\
             bash -c {scan} scan \"$lock\" '' 0\n",
            scan = shell_quote(SCAN_SH),
        );
        let out = self.ssh_output(&format!("sudo -n bash -c {}", shell_quote(&script)))?;
        Ok(LockReport::parse(&out))
    }

    fn unlock(&self, args: &[String]) -> Result<(), String> {
        let mut force = false;
        for a in args {
            match a.as_str() {
                "--force" => force = true,
                other => return Err(format!("unlock: unknown option {other}\n{HELP}")),
            }
        }
        if self.require()? != "running" {
            println!("{NAME} is not running: no round, no lock (it lives in /run)");
            return Ok(());
        }
        let report = self.lock_report()?;
        let alive = owner_alive(&report.owner);
        print!("{}", report.describe(alive, &round_alive));
        let to_end = orphans(&report.procs, alive, &round_alive);
        if to_end.is_empty() {
            if report.busy && alive == Some(true) {
                println!(
                    "the round holding the lock is alive on this host: wait for it, or stop that \
                     `cargo xtask vm-lab run` (Ctrl-C) and run unlock again"
                );
            } else if report.busy {
                println!(
                    "nothing here is safe to end automatically; end the holders above by hand \
                     (`cargo xtask vm-lab ssh sudo kill <pid>`)"
                );
            } else {
                println!("nothing to clean up");
            }
            return Ok(());
        }
        if !force {
            println!(
                "would end {} process(es) of rounds whose `vm-lab run` is gone: {}",
                to_end.len(),
                pid_list(&to_end)
            );
            println!("run `cargo xtask vm-lab unlock --force` to end them and free the lock");
            return Ok(());
        }
        let pids = pid_list(&to_end);
        // TERM first, KILL what is still there after ~5 s.
        let kill = format!(
            "kill -TERM {pids} 2>/dev/null\n\
             for i in $(seq 10); do\n\
               alive=; for p in {pids}; do kill -0 $p 2>/dev/null && alive=\"$alive $p\"; done\n\
               [ -z \"$alive\" ] && break; sleep 0.5\n\
             done\n\
             [ -n \"$alive\" ] && kill -KILL $alive\n\
             flock -n {LOCK} sh -c ': > {LOCK}.owner' 2>/dev/null\n\
             true\n"
        );
        self.ssh_output(&format!("sudo -n bash -c {}", shell_quote(&kill)))?;
        println!("ended: {pids}");
        let after = self.lock_report()?;
        if after.busy {
            let alive = owner_alive(&after.owner);
            print!("{}", after.describe(alive, &round_alive));
            Err("the lock is still held".into())
        } else {
            println!("the VM lock is free");
            Ok(())
        }
    }
}

/// A shell line printing the pids of live rounds whose command runs in
/// `<dir>/src` (the `( cd <dir>/src ||` of `round_script`), one per line.
fn same_dir_rounds_check(dir: &str) -> String {
    let needle = shell_quote(&format!("( cd {dir}/src ||"));
    format!(
        "sudo env -u {ROUND_VAR} bash -c {}",
        shell_quote(&format!(
            "for f in $(grep -lazs '^{ROUND_VAR}=' /proc/[0-9]*/environ); do \
             p=${{f#/proc/}}; p=${{p%%/*}}; \
             tr '\\0' ' ' < /proc/$p/cmdline 2>/dev/null | grep -qF -- {needle} && echo $p; \
             done; true"
        ))
    )
}

/// What a `run` script needs to know about its round.
struct Round<'a> {
    lock: &'a str,
    /// `/srv/lab/<worktree>`; the command runs in `<dir>/src`.
    dir: &'a str,
    /// Already a shell line (`remote_command`).
    cmd: &'a str,
    exclusive: bool,
    timeout_s: u64,
    id: &'a str,
    host_pid: u32,
}

/// Lists the processes of a round (`$2`, or every round when empty) and
/// the ones holding the lock file `$1` open, skipping pid `$3`: one line
/// `pid<TAB>round<TAB>hold|wait|-<TAB>age s<TAB>command` each. Runs without
/// the round mark in its own environment, so it never lists itself.
const SCAN_SH: &str = r#"lock=$1 want=$2 skip=$3
ino=$(stat -Lc %i "$lock" 2>/dev/null)
waiters=" $(awk -v s=":$ino" '$2 == "->" && substr($7, length($7) - length(s) + 1) == s { print $6 }' /proc/locks 2>/dev/null | tr '\n' ' ') "
pids=$( { grep -lazs '^COREROUTER_LAB_ROUND=' /proc/[0-9]*/environ; find /proc/[0-9]*/fd -maxdepth 1 -lname "$lock" 2>/dev/null; } | cut -d/ -f3 | sort -un)
for pid in $pids; do
  [ "$pid" = "$skip" ] && continue
  round=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null | sed -n 's/^COREROUTER_LAB_ROUND=//p' | head -n 1)
  if [ -n "$want" ] && [ "$round" != "$want" ]; then continue; fi
  fd=-
  if find "/proc/$pid/fd" -maxdepth 1 -lname "$lock" 2>/dev/null | grep -q .; then
    case "$waiters" in *" $pid "*) fd=wait ;; *) fd=hold ;; esac
  fi
  age=$(ps -o etimes= -p "$pid" 2>/dev/null | tr -d ' ')
  [ -n "$age" ] || continue
  cmd=$(tr '\0\n\t' '   ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c 1-200)
  printf '%s\t%s\t%s\t%s\t%s\n' "$pid" "${round:--}" "$fd" "$age" "$cmd"
done
"#;

/// Helpers every round script starts with: `lab_owner` describes the owner
/// file, `lab_list` turns `SCAN_SH` lines into sentences, `lab_scan <round>`
/// runs it (into a file, never a pipe or `$( )`: a subshell of this one
/// would carry the round mark and the lock and list itself).
const ROUND_HELPERS_SH: &str = r#"lab_owner() {
  o=@LOCK@.owner
  if grep -q '^worktree=' "$o" 2>/dev/null; then
    s=$(sed -n 's/^started=//p' "$o")
    echo "$(sed -n 's/^worktree=//p' "$o") (host pid $(sed -n 's/^host_pid=//p' "$o"), for $(( $(date +%s) - ${s:-0} )) s)"
  elif [ -s "$o" ]; then cat "$o"
  else echo 'owner unknown'
  fi
}
lab_list() {
  awk -F'\t' '{ f = $3 == "hold" ? "holds the lock" : $3 == "wait" ? "waits for the lock" : "no lock"; printf "  pid %s (%s, round %s, up %s s): %s\n", $1, f, $2, $4, $5 }' "$1"
}
lab_scan_out=$(mktemp)
lab_scan() {
  env -u COREROUTER_LAB_ROUND bash -c @SCAN@ scan @LOCK@ "$1" $$ 9>&- > "$lab_scan_out"
}
"#;

/// The exclusive part: wait for the lock (with a deadline), then sign it.
/// Only the wait has a deadline, never the round.
const ROUND_LOCK_SH: &str = r#"exec 9>>@LOCK@
if ! flock -n 9; then
  echo "vm-lab: the VM is busy: $(lab_owner); waiting up to @TIMEOUT@ s for it (--lock-timeout)" >&2
  if ! flock -w @TIMEOUT@ 9; then
    echo "vm-lab: gave up after @TIMEOUT@ s waiting for @LOCK@; held by $(lab_owner)" >&2
    lab_scan ''
    lab_list "$lab_scan_out" >&2
    rm -f "$lab_scan_out"
    echo 'vm-lab: `cargo xtask vm-lab unlock` shows the holders and frees the lock of a round that is gone' >&2
    exit 75
  fi
fi
printf 'worktree=%s\nround=%s\nhost_pid=%s\nstarted=%s\n' @DIR@ @ID@ @PID@ "$(date +%s)" > @LOCK@.owner
"#;

/// The command, with the lock's fd closed (`9>&-`): a daemon it starts
/// (zebra, 2026-10-28) must not keep the lock after the round. Then the
/// leftovers check. `cd` on a line of its own: `cd x && a & b` would put
/// `cd x && a` in the background and run `b` outside `x`.
const ROUND_CMD_SH: &str = r#"( cd @DIR@/src || exit 1
@CMD@
) 9>&-
rc=$?
lab_scan @ID@
if [ -s "$lab_scan_out" ]; then
  echo "vm-lab: warning: the command left processes running in the VM:" >&2
  lab_list "$lab_scan_out" >&2
  echo 'vm-lab: stop them in the test itself (trap ... EXIT); they do not hold the lock, and `cargo xtask vm-lab unlock --force` ends them' >&2
fi
rm -f "$lab_scan_out"
"#;

/// The part of a `run` script after the toolchain setup.
fn round_script(r: &Round) -> String {
    let mut s = String::from(ROUND_HELPERS_SH);
    if r.exclusive {
        s.push_str(ROUND_LOCK_SH);
    }
    s.push_str(ROUND_CMD_SH);
    if r.exclusive {
        // Still ours here: a clean end leaves no stale owner behind.
        s.push_str(": > @LOCK@.owner\n");
    }
    s.push_str("exit $rc\n");
    // `@CMD@` last: the command's own text is never scanned for markers.
    s.replace("@SCAN@", &shell_quote(SCAN_SH))
        .replace("@LOCK@", &shell_quote(r.lock))
        .replace("@TIMEOUT@", &r.timeout_s.to_string())
        .replace("@DIR@", &shell_quote(r.dir))
        .replace("@ID@", &shell_quote(r.id))
        .replace("@PID@", &r.host_pid.to_string())
        .replace("@CMD@", r.cmd)
}

/// How a process uses the lock file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FdUse {
    None,
    Holds,
    Waits,
}

#[derive(Debug, PartialEq, Eq)]
struct LabProc {
    pid: u32,
    round: Option<String>,
    fd: FdUse,
    age_s: u64,
    cmd: String,
}

/// `<LOCK>.owner`: `key=value` lines since G0.26b; one free line
/// (`/srv/lab/<worktree> since 01:02:03Z`) from older `vm_lab.rs`.
#[derive(Debug, PartialEq, Eq)]
enum Owner {
    None,
    Round {
        worktree: String,
        round: String,
        host_pid: u32,
        started: u64,
    },
    Legacy(String),
}

impl Owner {
    fn parse(text: &str) -> Self {
        let get = |k: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')))
                .map(str::trim)
        };
        match (get("worktree"), get("round")) {
            (Some(w), Some(r)) => Owner::Round {
                worktree: w.to_owned(),
                round: r.to_owned(),
                host_pid: get("host_pid").and_then(|p| p.parse().ok()).unwrap_or(0),
                started: get("started").and_then(|p| p.parse().ok()).unwrap_or(0),
            },
            _ if text.trim().is_empty() => Owner::None,
            _ => Owner::Legacy(text.trim().to_owned()),
        }
    }
}

struct LockReport {
    busy: bool,
    now: u64,
    owner: Owner,
    procs: Vec<LabProc>,
}

impl LockReport {
    fn parse(text: &str) -> Self {
        let (head, rest) = text.split_once("--owner--\n").unwrap_or((text, ""));
        let (owner, procs) = rest.split_once("--procs--\n").unwrap_or((rest, ""));
        let busy = head.lines().any(|l| l.trim() == "lock=busy");
        let now = head
            .lines()
            .find_map(|l| l.trim().strip_prefix("now="))
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        Self {
            busy,
            now,
            owner: Owner::parse(owner),
            procs: procs.lines().filter_map(parse_proc).collect(),
        }
    }

    /// Who holds the lock and what is running, for `status` and `unlock`.
    fn describe(&self, owner_alive: Option<bool>, round_alive: &dyn Fn(&str) -> bool) -> String {
        let mut s = String::new();
        let alive = match owner_alive {
            Some(true) => "its `vm-lab run` is alive on this host",
            Some(false) => "its `vm-lab run` is gone",
            None => "unknown whether its round is alive",
        };
        if !self.busy {
            s.push_str("lock: free\n");
        } else {
            match &self.owner {
                Owner::Round {
                    worktree,
                    round,
                    host_pid,
                    started,
                } => s.push_str(&format!(
                    "lock: held by {worktree} (host pid {host_pid}, round {round}) for {}; {alive}\n",
                    human_secs(self.now.saturating_sub(*started))
                )),
                Owner::Legacy(text) => s.push_str(&format!(
                    "lock: held by {text} (owner from an older vm_lab.rs); {alive}\n"
                )),
                Owner::None => s.push_str("lock: held, owner unknown\n"),
            }
        }
        for p in &self.procs {
            let fd = match p.fd {
                FdUse::Holds => "holds the lock",
                FdUse::Waits => "waits for the lock",
                FdUse::None => "no lock",
            };
            let round = match &p.round {
                Some(r) if round_alive(r) => format!("round {r}, alive"),
                Some(r) => format!("round {r}, gone"),
                None => "no round mark".into(),
            };
            s.push_str(&format!(
                "  pid {} ({fd}; {round}; up {}): {}\n",
                p.pid,
                human_secs(p.age_s),
                p.cmd
            ));
        }
        s
    }
}

fn parse_proc(line: &str) -> Option<LabProc> {
    let mut f = line.splitn(5, '\t');
    let pid = f.next()?.trim().parse().ok()?;
    let round = match f.next()?.trim() {
        "-" | "" => None,
        r => Some(r.to_owned()),
    };
    let fd = match f.next()?.trim() {
        "hold" => FdUse::Holds,
        "wait" => FdUse::Waits,
        _ => FdUse::None,
    };
    let age_s = f.next()?.trim().parse().unwrap_or(0);
    let cmd = f.next().unwrap_or("").trim().to_owned();
    Some(LabProc {
        pid,
        round,
        fd,
        age_s,
        cmd,
    })
}

/// What `unlock --force` may end: a process of a round whose `vm-lab run`
/// is gone, or a holder of the lock without a round mark (an older
/// `vm_lab.rs`) when the owner's round is known to be gone. Never a live
/// round, never a waiter.
fn orphans<'a>(
    procs: &'a [LabProc],
    owner_alive: Option<bool>,
    round_alive: &dyn Fn(&str) -> bool,
) -> Vec<&'a LabProc> {
    procs
        .iter()
        .filter(|p| match &p.round {
            Some(r) => !round_alive(r),
            None => p.fd == FdUse::Holds && owner_alive == Some(false),
        })
        .collect()
}

fn pid_list(procs: &[&LabProc]) -> String {
    procs
        .iter()
        .map(|p| p.pid.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

/// This `vm-lab run`'s round mark: `<pid>.<start time in ticks>`, so a
/// reused pid is not taken for the same round.
fn own_round() -> String {
    let pid = std::process::id();
    format!("{pid}.{}", start_ticks(pid).unwrap_or(0))
}

/// Field 22 of `/proc/<pid>/stat`.
fn start_ticks(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `pid (comm) state …`: comm may hold spaces, so count after `)`.
    let (_, rest) = stat.rsplit_once(')')?;
    rest.split_whitespace().nth(19)?.parse().ok()
}

/// Is the `vm-lab run` behind a round mark still running on this host?
fn round_alive(round: &str) -> bool {
    let Some((pid, start)) = round.split_once('.') else {
        return false;
    };
    let (Ok(pid), Ok(start)) = (pid.parse::<u32>(), start.parse::<u64>()) else {
        return false;
    };
    match start_ticks(pid) {
        Some(t) => start == 0 || t == start,
        None => false,
    }
}

/// `None` when nobody signed the lock. An owner from an older `vm_lab.rs`
/// is alive while some `vm-lab run` works in that worktree on this host.
fn owner_alive(owner: &Owner) -> Option<bool> {
    match owner {
        Owner::None => None,
        Owner::Round { round, .. } => Some(round_alive(round)),
        Owner::Legacy(text) => {
            let dir = text.split_whitespace().next().unwrap_or("");
            let name = dir.rsplit('/').next().unwrap_or("");
            if name.is_empty() {
                return None;
            }
            Some(host_run_in(name))
        }
    }
}

/// Some process on this host runs `vm-lab run` from a worktree called `name`.
fn host_run_in(name: &str) -> bool {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return false;
    };
    entries.flatten().any(|e| {
        let path = e.path();
        let cmdline = std::fs::read(path.join("cmdline")).unwrap_or_default();
        let args: Vec<&[u8]> = cmdline.split(|b| *b == 0).collect();
        let is_run = args.iter().any(|a| *a == b"vm-lab") && args.iter().any(|a| *a == b"run");
        is_run
            && std::fs::read_link(path.join("cwd"))
                .is_ok_and(|cwd| cwd.components().any(|c| c.as_os_str() == name))
    })
}

/// `900`, `90s`, `30m`, `1h` → seconds (at most a day).
fn parse_duration(text: &str) -> Result<u64, String> {
    let t = text.trim();
    let (num, mult) = if let Some(n) = t.strip_suffix('s') {
        (n, 1)
    } else if let Some(n) = t.strip_suffix('m') {
        (n, 60)
    } else if let Some(n) = t.strip_suffix('h') {
        (n, 3600)
    } else {
        (t, 1)
    };
    let n: u64 = num
        .parse()
        .map_err(|_| format!("{text:?}: a number of seconds, or with s/m/h (30m)"))?;
    let secs = n.saturating_mul(mult);
    if secs > 24 * 3600 {
        return Err(format!("{text:?}: at most 24h"));
    }
    Ok(secs)
}

fn human_secs(s: u64) -> String {
    match s {
        0..60 => format!("{s} s"),
        60..3600 => format!("{}m{:02}s", s / 60, s % 60),
        _ => format!("{}h{:02}m", s / 3600, (s % 3600) / 60),
    }
}

fn parse_spec(args: &[String]) -> Result<Spec, String> {
    let mut spec = Spec {
        cpus: 8,
        memory_mib: 16_384,
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

/// The user runs `flock vm/root.lock cargo xtask vm-lab tools`: the lock
/// is then theirs for this very command, not another round. Linux only:
/// walks the parent chain in /proc looking for that `flock`.
fn held_by_ancestor(lock: &Path) -> bool {
    let lock = lock.to_string_lossy();
    let mut pid = std::process::id().to_string();
    for _ in 0..32 {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        // `pid (comm) state ppid …`: comm may hold spaces, so cut after `)`.
        let Some(ppid) = stat
            .rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(1))
        else {
            return false;
        };
        if ppid == "0" || ppid == "1" {
            return false;
        }
        let cmdline = std::fs::read(format!("/proc/{ppid}/cmdline")).unwrap_or_default();
        let args: Vec<String> = cmdline
            .split(|b| *b == 0)
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        let is_flock = args
            .first()
            .is_some_and(|a| a.rsplit('/').next() == Some("flock"));
        if is_flock
            && args
                .iter()
                .any(|a| *a == lock || lock.ends_with(a.as_str()))
        {
            return true;
        }
        pid = ppid.to_owned();
    }
    false
}

/// The Ubuntu cloud image in `base`, downloaded once and checked against the published
/// SHA256SUMS; a mismatch is refused (and the file removed).
pub(crate) fn cloud_image(base: &Path) -> Result<PathBuf, String> {
    let sums = base.join("SHA256SUMS");
    let img = base.join(IMAGE);
    let part = base.join(format!("{IMAGE}.part"));
    if !sums.exists() {
        download(&format!("{IMAGE_URL}SHA256SUMS"), &sums)?;
    }
    let text = std::fs::read_to_string(&sums).map_err(|e| format!("{}: {e}", sums.display()))?;
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
            "{} does not match SHA256SUMS ({want}); remove that directory to download again",
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

/// The last IPv4 of the management NIC in a `virsh domifaddr` table, where
/// a row whose name is `-` continues the NIC above it.
pub(crate) fn mgmt_ipv4(table: &str, mgmt_mac: &str) -> Option<String> {
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
        if mac.eq_ignore_ascii_case(mgmt_mac) && *proto == "ipv4" {
            found = addr.split('/').next().map(str::to_owned);
        }
    }
    found
}

pub(crate) fn check_snapshot_name(name: &str) -> Result<(), String> {
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

pub(crate) fn shell_quote(s: &str) -> String {
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

pub(crate) fn virsh(args: &[&str]) -> Result<String, String> {
    output(Command::new("virsh").args(["-c", URI]).args(args))
}

pub(crate) fn output(cmd: &mut Command) -> Result<String, String> {
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

pub(crate) fn run_ok(cmd: &mut Command) -> Result<(), String> {
    output(cmd).map(|_| ())
}

pub(crate) fn download(url: &str, to: &Path) -> Result<(), String> {
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

pub(crate) fn sha256_file(path: &Path) -> Result<String, String> {
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

pub(crate) fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

pub(crate) fn write(path: &Path, text: &str) -> Result<(), String> {
    std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
}

pub(crate) fn unix_now() -> u64 {
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
        assert_eq!(
            mgmt_ipv4(table, MGMT_MAC).as_deref(),
            Some("192.168.122.47")
        );
        assert_eq!(mgmt_ipv4(" Name MAC Protocol Address\n", MGMT_MAC), None);
    }

    #[test]
    fn spec_flags_are_checked() {
        let s = parse_spec(&["--cpus".into(), "16".into(), "--wires".into(), "2".into()]).unwrap();
        assert_eq!((s.cpus, s.wires, s.memory_mib), (16, 2, 16_384));
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

    fn round<'a>(lock: &'a str, dir: &'a str, cmd: &'a str, timeout_s: u64) -> Round<'a> {
        Round {
            lock,
            dir,
            cmd,
            exclusive: true,
            timeout_s,
            id: "4242.77",
            host_pid: 4242,
        }
    }

    /// The check finds a live round of the same worktree and only that one
    /// (run here without `sudo`: the processes are this user's).
    #[test]
    fn same_dir_rounds_check_finds_a_queued_round_of_this_worktree() {
        let tmp = std::env::temp_dir().join(format!("vm-lab-check-{}", std::process::id()));
        let dir = tmp.join("w").display().to_string();
        std::fs::create_dir_all(format!("{dir}/src")).unwrap();
        std::fs::create_dir_all(format!("{dir}-other/src")).unwrap();
        let spawn = |d: &str| {
            std::process::Command::new("env")
                .arg(format!("{ROUND_VAR}=1.2"))
                .args(["bash", "-c"])
                .arg(format!("( cd {d}/src || exit 1\nsleep 30\n) 9>&-"))
                .spawn()
                .unwrap()
        };
        let mut same = spawn(&dir);
        let mut other = spawn(&format!("{dir}-other"));
        std::thread::sleep(std::time::Duration::from_millis(200));
        let check = same_dir_rounds_check(&dir);
        let local = check.strip_prefix("sudo ").unwrap();
        let out = std::process::Command::new("bash")
            .args(["-c", local])
            .output()
            .unwrap();
        let _ = same.kill();
        let _ = other.kill();
        let _ = same.wait();
        let _ = other.wait();
        let _ = std::fs::remove_dir_all(&tmp);
        let pids = String::from_utf8(out.stdout).unwrap();
        let pids: Vec<&str> = pids.split_whitespace().collect();
        assert_eq!(pids, vec![same.id().to_string().as_str()]);
        assert!(same_dir_rounds_check("/srv/lab/none").starts_with("sudo env -u"));
    }

    #[test]
    fn round_script_closes_the_lock_for_the_command_and_waits_with_a_deadline() {
        let s = round_script(&round(LOCK, "/srv/lab/w", "cargo test && echo ok", 1800));
        // The command runs with fd 9 closed (2026-10-28: zebra kept it).
        assert!(s.contains("( cd /srv/lab/w/src || exit 1\ncargo test && echo ok\n) 9>&-"));
        assert!(s.contains("flock -w 1800 9"));
        // No wait without a deadline.
        assert!(!s.contains("flock 9"));
        assert!(s.contains("round=%s\\nhost_pid=%s"));
        assert!(s.contains("/srv/lab/w 4242.77 4242"));
        assert!(s.contains("exit 75"));
        // Shared rounds take no lock but still look for leftovers.
        let shared = round_script(&Round {
            exclusive: false,
            ..round(LOCK, "/srv/lab/w", "cargo build", 1800)
        });
        assert!(!shared.contains("flock"));
        assert!(shared.contains("lab_scan 4242.77"));
    }

    #[test]
    fn owner_and_report_parse() {
        let text = "lock=busy\nnow=1000\n--owner--\nworktree=/srv/lab/w\nround=12.34\n\
                    host_pid=12\nstarted=700\n--procs--\n\
                    501\t12.34\thold\t300\tbash -c script\n\
                    502\t-\thold\t290\t/usr/lib/frr/zebra -d\n\
                    503\t-\twait\t10\tbash -c old\n\
                    junk\n";
        let r = LockReport::parse(text);
        assert!(r.busy);
        assert_eq!(r.now, 1000);
        assert_eq!(
            r.owner,
            Owner::Round {
                worktree: "/srv/lab/w".into(),
                round: "12.34".into(),
                host_pid: 12,
                started: 700,
            }
        );
        assert_eq!(r.procs.len(), 3);
        assert_eq!(r.procs[1].cmd, "/usr/lib/frr/zebra -d");
        assert_eq!(r.procs[2].fd, FdUse::Waits);
        let d = r.describe(Some(false), &|_| false);
        assert!(d.contains("held by /srv/lab/w (host pid 12, round 12.34) for 5m00s"));
        assert!(d.contains("pid 502 (holds the lock; no round mark"));
        assert_eq!(
            Owner::parse("/srv/lab/old since 01:02:03Z\n"),
            Owner::Legacy("/srv/lab/old since 01:02:03Z".into())
        );
        assert_eq!(Owner::parse("\n"), Owner::None);
        assert!(!LockReport::parse("lock=free\nnow=1\n--owner--\n--procs--\n").busy);
    }

    #[test]
    fn unlock_ends_only_what_a_dead_round_left() {
        let p = |pid, round: Option<&str>, fd| LabProc {
            pid,
            round: round.map(str::to_owned),
            fd,
            age_s: 1,
            cmd: String::new(),
        };
        let procs = [
            p(1, Some("live.1"), FdUse::Holds),
            p(2, Some("dead.1"), FdUse::None),
            p(3, None, FdUse::Holds),
            p(4, None, FdUse::Waits),
        ];
        let alive = |r: &str| r.starts_with("live");
        let pids = |v: Vec<&LabProc>| v.iter().map(|p| p.pid).collect::<Vec<_>>();
        // Owner gone (the 2026-10-28 case): its unmarked holder goes too.
        assert_eq!(pids(orphans(&procs, Some(false), &alive)), [2, 3]);
        // Owner alive or unknown: only marked leftovers of dead rounds.
        assert_eq!(pids(orphans(&procs, Some(true), &alive)), [2]);
        assert_eq!(pids(orphans(&procs, None, &alive)), [2]);
    }

    #[test]
    fn rounds_are_alive_while_their_host_process_is() {
        assert!(round_alive(&own_round()));
        let pid = std::process::id();
        assert!(!round_alive(&format!("{pid}.1")));
        assert!(!round_alive("garbage"));
        assert!(!round_alive("4000000000.5"));
    }

    #[test]
    fn durations_parse() {
        assert_eq!(parse_duration("900").unwrap(), 900);
        assert_eq!(parse_duration("90s").unwrap(), 90);
        assert_eq!(parse_duration("30m").unwrap(), 1800);
        assert_eq!(parse_duration("1h").unwrap(), 3600);
        assert!(parse_duration("25h").is_err());
        assert!(parse_duration("m").is_err());
        assert!(parse_duration("-1").is_err());
        assert_eq!(human_secs(42), "42 s");
        assert_eq!(human_secs(312), "5m12s");
        assert_eq!(human_secs(3720), "1h02m");
    }

    /// The real script, run by bash on this machine with a lock file in a
    /// temporary folder (what the VM does as root, minus the root).
    #[cfg(target_os = "linux")]
    mod shell {
        use super::*;

        fn scratch(tag: &str) -> PathBuf {
            let d = std::env::temp_dir().join(format!(
                "vm-lab-{tag}-{}-{}",
                std::process::id(),
                unix_now()
            ));
            std::fs::create_dir_all(d.join("src")).unwrap();
            d
        }

        fn have_tools() -> bool {
            ["bash", "flock"].iter().all(|t| {
                Command::new(t)
                    .arg("--version")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok()
            })
        }

        fn lock_free(lock: &Path) -> bool {
            Command::new("flock")
                .arg("-n")
                .arg(lock)
                .arg("true")
                .status()
                .unwrap()
                .success()
        }

        fn run_round(r: &Round) -> std::process::Output {
            Command::new("env")
                .arg(format!("{ROUND_VAR}={}", r.id))
                .args(["bash", "-c"])
                .arg(round_script(r))
                .stdin(Stdio::null())
                .output()
                .unwrap()
        }

        /// Pids named in the `lab_list` lines of `text`.
        fn listed_pids(text: &str) -> Vec<u32> {
            text.lines()
                .filter_map(|l| l.trim().strip_prefix("pid "))
                .filter_map(|l| l.split_whitespace().next()?.parse().ok())
                .collect()
        }

        #[test]
        fn a_background_process_does_not_keep_the_lock() {
            if !have_tools() {
                eprintln!("skip: no bash/flock");
                return;
            }
            let d = scratch("leak");
            let lock = d.join("lock");
            let (l, dir) = (lock.to_string_lossy(), d.to_string_lossy());
            let id = format!("t{}.1", std::process::id());
            let r = Round {
                id: &id,
                ..round(&l, &dir, "sleep 600 >/dev/null 2>&1 & echo started", 5)
            };
            let out = run_round(&r);
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(out.status.success(), "{err}");
            assert!(String::from_utf8_lossy(&out.stdout).contains("started"));
            // The round ended; its `sleep` lives on but holds no lock.
            let free = lock_free(&lock);
            assert!(err.contains("left processes running"), "{err}");
            assert!(err.contains("sleep 600"), "{err}");
            let left = listed_pids(&err);
            for pid in &left {
                let _ = Command::new("kill").arg(pid.to_string()).status();
            }
            assert!(!left.is_empty());
            assert!(free, "a process of the round kept the lock");
            // A clean end leaves no owner behind.
            assert_eq!(std::fs::read_to_string(d.join("lock.owner")).unwrap(), "");
            let _ = std::fs::remove_dir_all(&d);
        }

        #[test]
        fn the_wait_gives_up_and_says_who_holds_it() {
            if !have_tools() {
                eprintln!("skip: no bash/flock");
                return;
            }
            let d = scratch("wait");
            let lock = d.join("lock");
            std::fs::write(
                d.join("lock.owner"),
                "worktree=/srv/lab/other\nround=1.1\nhost_pid=1\nstarted=0\n",
            )
            .unwrap();
            let mut holder = Command::new("flock")
                .arg(&lock)
                .args(["bash", "-c", "sleep 30\ntrue"])
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            while lock_free(&lock) && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(20));
            }
            let (l, dir) = (lock.to_string_lossy(), d.to_string_lossy());
            let started = Instant::now();
            let out = run_round(&round(&l, &dir, "echo never", 1));
            let _ = holder.kill();
            let _ = holder.wait();
            let err = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(75), "{err}");
            assert!(started.elapsed() < Duration::from_secs(10));
            assert!(!String::from_utf8_lossy(&out.stdout).contains("never"));
            assert!(err.contains("gave up after 1 s"), "{err}");
            assert!(err.contains("held by /srv/lab/other (host pid 1"), "{err}");
            assert!(err.contains("holds the lock"), "{err}");
            // Multi-line command lines (a round's own `bash -c`) stay on one line.
            assert!(
                err.lines()
                    .filter(|l| l.starts_with("  pid "))
                    .all(|l| l.contains("): ")),
                "{err}"
            );
            assert!(err.contains("vm-lab unlock"), "{err}");
            let _ = std::fs::remove_dir_all(&d);
        }
    }
}

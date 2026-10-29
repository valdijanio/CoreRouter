//! `cargo xtask ci-runner <subcommand>` — the self-hosted GitHub Actions
//! runner of the queue's batches, in a disposable libvirt VM of its own
//! (`corerouter-ci`), never on the host. Details, security model and
//! operation: `docs/ci-runner.md`.
//!
//! The repository is public, so the runner must only ever run trusted code:
//!
//! - the workflow routes to it only `workflow_dispatch` on `queue/*` (the
//!   queue's batches) and, when the user turns it on, `push` to `main`;
//! - the runner itself refuses anything else: a job-started hook, root-owned
//!   and set in the systemd unit (out of the job's reach), fails the job
//!   before any step unless event, ref and repository match ([`JOB_STARTED`]);
//! - the jobs run as `runner`, a user without `sudo`; the VM reaches the
//!   internet through libvirt's NAT and nothing else: a host-side nwfilter
//!   (root in the VM cannot lift it) drops private ranges, the host's own
//!   addresses and IPv6 ([`egress_filter`]);
//! - the disk goes back to the `registered` snapshot every N jobs
//!   (`reset --if-due`, run by the queue between batches); the build caches
//!   live on a second disk that survives it.
//!
//! The registration token is the user's: `register` reads it from the
//! terminal and sends it to the VM over SSH stdin, never in an argument or a
//! file. Nothing here changes GitHub's configuration.

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::Outcome;
use crate::vm_lab::{
    check_snapshot_name, cloud_image, download, mgmt_ipv4, output, read, run_ok, sha256_file,
    shell_quote, unix_now, virsh, write,
};

const NAME: &str = "corerouter-ci";
const URI: &str = "qemu:///system";
/// Not the lab's (`…:01`): both VMs share libvirt's `default` network.
const MGMT_MAC: &str = "52:54:00:c0:72:11";
/// SSH login with `sudo`, for the host's maintenance only.
const ADMIN: &str = "ciadmin";
/// Who runs the jobs: no `sudo`, no SSH key.
const RUNNER: &str = "runner";
const REPO: &str = "valdijanio/CoreRouter";
/// The label the workflow asks for (`runs-on: [self-hosted, corerouter]`).
const LABEL: &str = "corerouter";
/// actions/runner release, pinned like `vm_tools` (the runner updates
/// itself afterwards, as GitHub requires).
const RUNNER_VERSION: &str = "2.338.2";
const RUNNER_SHA256: &str = "baebf204307bac6193480852732f0aba2ae97b6c5597c244f4d5558390147c40";
const FILTER: &str = "corerouter-ci-egress";
/// The second disk: build caches, kept across resets.
const CACHE: &str = "/var/cache/corerouter-ci";
/// Hooks, unit environment: root-owned.
const ETC: &str = "/etc/corerouter-ci";
/// Job counter and log, written by the hooks (as `runner`).
const STATE: &str = "/var/lib/corerouter-ci";
/// Busy marks and the `cargo xtask ci` slots (tmpfs, shared by the runners).
const RUN: &str = "/run/corerouter-ci";
/// Taken after `create` (provisioned, not registered) and after `register`.
const BASE_SNAPSHOT: &str = "base";
const REGISTERED_SNAPSHOT: &str = "registered";
/// `reset --if-due` without a number: ~10 batches of 4 jobs.
const DUE_DEFAULT: u64 = 40;

const PACKAGES: &[&str] = &[
    "build-essential",
    "clang",
    "llvm",
    "pkg-config",
    "iproute2",
    "iputils-ping",
    "ethtool",
    "nftables",
    "git",
    "curl",
    "jq",
    "rsync",
    "zstd",
    "qemu-guest-agent",
    // What eframe/winit/wgpu need to compile (the same list as
    // .github/actions/setup).
    "libxkbcommon-dev",
    "libxkbcommon-x11-dev",
    "libwayland-dev",
    "libx11-dev",
    "libxcursor-dev",
    "libxrandr-dev",
    "libxi-dev",
    "libxcb-render0-dev",
    "libxcb-shape0-dev",
    "libxcb-xfixes0-dev",
    "libgl1-mesa-dev",
    // HWE (7.0, like the host and the lab) brings linux-modules-extra:
    // vrf, mpls_router, sctp…
    "linux-generic-hwe-24.04",
];

const HELP: &str = "usage: cargo xtask ci-runner <subcommand>   (docs/ci-runner.md)
  create [--cpus N] [--memory MiB] [--disk GiB] [--cache GiB] [--runners N]
                    VM corerouter-ci in $COREROUTER_CI_RUNNER_DIR (default /srv/build/ci-runner):
                    verified Ubuntu image, egress filter, packages, Rust, the runner
                    (pinned + SHA-256), hooks; checks the network; snapshot `base`
                    (defaults: 16 vCPUs, 16384 MiB, 40 GiB system, 200 GiB cache, 3 runners)
  provision [--runners N]
                    run the provisioning again on the existing VM (idempotent) and retake `base`
  register          THE USER RUNS THIS: asks for the registration token (GitHub → Settings →
                    Actions → Runners → New self-hosted runner), registers the runners,
                    starts them and takes the snapshot `registered`
  status            VM, runners, busy jobs, job counter, recent verdicts, filter, GitHub view
  check-network     from inside the VM: internet yes; LAN, host and IPv6 no
  up | down         start (and wait for SSH) | shut down
  ssh [cmd...]      shell (or one command) as `ciadmin` (sudo inside the VM)
  run [--rev <git-rev>] [--slot N] -- <cmd...>
                    run <cmd> as `runner` in a fresh export of <git-rev> (default HEAD), with
                    the runners' environment and target dir /var/cache/corerouter-ci/target-try<N>
  reset [--if-due [N]] [--wipe-cache] [--force]
                    back to `registered` (else `base`); the cache disk stays. --if-due: only
                    when N jobs ran since (default 40); refused while a job runs, unless --force
  unregister [--yes]
                    THE USER RUNS THIS: removes the corerouter-ci-* runners from GitHub
                    (gh api); without --yes only lists them
  destroy           delete the VM, its disks and the filter (the cached image stays)";

pub fn main(root: &Path, args: &[String]) -> Outcome {
    let vm = match Vm::new(root) {
        Ok(v) => v,
        Err(e) => return Outcome::Fail(e),
    };
    let (sub, rest) = match args.split_first() {
        Some((s, r)) => (s.as_str(), r),
        None => ("", &[][..]),
    };
    let result = match sub {
        "create" => vm.create(rest),
        "provision" => parse_spec(rest).and_then(|spec| {
            vm.runner_tarball()
                .and_then(|tgz| vm.provision(&spec, &tgz))
        }),
        "register" => vm.register(),
        "status" => vm.status(),
        "check-network" => vm.up().and_then(|()| vm.check_network()),
        "up" => vm.up(),
        "down" => vm.down(),
        "ssh" => vm.ssh_interactive(rest),
        "run" => vm.run(rest),
        "reset" => vm.reset_cmd(rest),
        "unregister" => unregister(rest),
        "destroy" => vm.destroy(),
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

#[derive(Debug, PartialEq)]
struct Spec {
    cpus: u32,
    memory_mib: u32,
    disk_gib: u32,
    cache_gib: u32,
    runners: u32,
}

fn parse_spec(args: &[String]) -> Result<Spec, String> {
    let mut spec = Spec {
        cpus: 16,
        memory_mib: 16384,
        disk_gib: 40,
        cache_gib: 200,
        runners: 3,
    };
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it
            .next()
            .ok_or_else(|| format!("{flag} needs a value\n{HELP}"))?;
        let n: u32 = value
            .parse()
            .map_err(|_| format!("{flag}: {value:?} is not a number"))?;
        let (slot, lo, hi) = match flag.as_str() {
            "--cpus" => (&mut spec.cpus, 2, 28),
            "--memory" => (&mut spec.memory_mib, 4096, 49152),
            "--disk" => (&mut spec.disk_gib, 20, 200),
            "--cache" => (&mut spec.cache_gib, 50, 800),
            "--runners" => (&mut spec.runners, 1, 8),
            other => return Err(format!("unknown option {other}\n{HELP}")),
        };
        if !(lo..=hi).contains(&n) {
            return Err(format!("{flag} must be between {lo} and {hi}"));
        }
        *slot = n;
    }
    Ok(spec)
}

struct Vm {
    root: PathBuf,
    dir: PathBuf,
}

impl Vm {
    fn new(root: &Path) -> Result<Self, String> {
        let dir = match std::env::var_os("COREROUTER_CI_RUNNER_DIR") {
            Some(d) => PathBuf::from(d),
            None if Path::new("/srv/build").is_dir() => PathBuf::from("/srv/build/ci-runner"),
            None => {
                return Err(
                    "no /srv/build: set COREROUTER_CI_RUNNER_DIR to a disk with ~250 GB free"
                        .into(),
                );
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

    // ---- create -------------------------------------------------------

    fn create(&self, args: &[String]) -> Result<(), String> {
        let spec = parse_spec(args)?;
        if self.state()?.is_some() {
            return Err(format!(
                "{NAME} already exists: `cargo xtask ci-runner destroy` first (or `reset`)"
            ));
        }
        let started = Instant::now();
        std::fs::create_dir_all(self.path("base"))
            .map_err(|e| format!("{}: {e}", self.dir.display()))?;
        let base = cloud_image(&self.path("base"))?;
        let runner_tgz = self.runner_tarball()?;
        self.keys()?;
        self.seed()?;
        let system = self.path(&format!("{NAME}.qcow2"));
        let cache = self.path(&format!("{NAME}-cache.qcow2"));
        for f in [&system, &cache] {
            let _ = std::fs::remove_file(f);
        }
        run_ok(Command::new("qemu-img").args([
            "create",
            "-q",
            "-f",
            "qcow2",
            "-F",
            "qcow2",
            "-b",
            &base.to_string_lossy(),
            &system.to_string_lossy(),
            &format!("{}G", spec.disk_gib),
        ]))?;
        run_ok(Command::new("qemu-img").args([
            "create",
            "-q",
            "-f",
            "qcow2",
            &cache.to_string_lossy(),
            &format!("{}G", spec.cache_gib),
        ]))?;
        self.define_filter()?;
        let xml = self.path(&format!("{NAME}.xml"));
        write(
            &xml,
            &domain_xml(&spec, &system, &cache, &self.path("seed.iso")),
        )?;
        virsh(&["define", &xml.to_string_lossy()])?;
        virsh(&["start", NAME])?;
        eprintln!("ci-runner: {NAME} defined and started; waiting for cloud-init (packages)…");
        self.wait_ssh(Duration::from_secs(900))?;
        let status =
            self.ssh_output("cloud-init status --wait >/dev/null; cloud-init status --long; true")?;
        eprintln!("{}", status.trim());
        if !status.contains("status: done") {
            return Err(format!("cloud-init did not finish:\n{status}"));
        }
        if self
            .ssh_output("test -e /var/run/reboot-required && echo yes; true")?
            .contains("yes")
        {
            eprintln!("ci-runner: rebooting into the new kernel…");
            self.down()?;
            self.up()?;
        }
        eprintln!("ci-runner: kernel {}", self.ssh_output("uname -r")?.trim());
        self.provision(&spec, &runner_tgz)?;
        eprintln!(
            "ci-runner: {NAME} ready in {:.0} s ({} vCPUs, {} MiB, {} runner(s)).\n\
             Next, the user registers it: `cargo xtask ci-runner register` (docs/ci-runner.md)",
            started.elapsed().as_secs_f64(),
            spec.cpus,
            spec.memory_mib,
            spec.runners
        );
        Ok(())
    }

    /// Everything after cloud-init, idempotent: `create` runs it, and
    /// `provision` runs it again on an existing VM (a fix to the script, a
    /// new runner version), ending in a fresh `base` snapshot.
    fn provision(&self, spec: &Spec, runner_tgz: &Path) -> Result<(), String> {
        self.up()?;
        self.put(runner_tgz, "/tmp/actions-runner.tar.gz")?;
        self.put(
            &self.root.join("rust-toolchain.toml"),
            "/tmp/rust-toolchain.toml",
        )?;
        self.ssh_root_script(&provision_script(spec, &self.kernel_modules()?))?;
        // Ejected once; a second eject (re-provisioning) fails harmlessly.
        let _ = virsh(&["change-media", NAME, "sda", "--eject", "--config"]);
        // Kernel modules and sysctls of the provisioning take effect on boot.
        self.down()?;
        self.up()?;
        self.check_network()?;
        self.snapshot(BASE_SNAPSHOT)
    }

    /// The actions/runner tarball, downloaded once and checked against the
    /// pinned SHA-256.
    fn runner_tarball(&self) -> Result<PathBuf, String> {
        let file = format!("actions-runner-linux-x64-{RUNNER_VERSION}.tar.gz");
        let path = self.path("base").join(&file);
        if !path.exists() {
            let part = self.path("base").join(format!("{file}.part"));
            eprintln!("ci-runner: downloading {file}…");
            download(
                &format!(
                    "https://github.com/actions/runner/releases/download/v{RUNNER_VERSION}/{file}"
                ),
                &part,
            )?;
            std::fs::rename(&part, &path).map_err(|e| format!("{}: {e}", path.display()))?;
        }
        let have = sha256_file(&path)?;
        if have != RUNNER_SHA256 {
            let _ = std::fs::remove_file(&path);
            return Err(format!(
                "checksum mismatch for {file}: got {have}, pinned {RUNNER_SHA256}; file removed"
            ));
        }
        Ok(path)
    }

    /// `(module, variable, optional)` from `ci/kernel-modules/` plus `vrf`
    /// (the setup action loads it on its own).
    fn kernel_modules(&self) -> Result<Vec<(String, String, bool)>, String> {
        let dir = self.root.join("ci/kernel-modules");
        let mut mods = vec![("vrf".to_owned(), "COREROUTER_REQUIRE_VRF".to_owned(), false)];
        let entries = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name == "README.md" {
                continue;
            }
            let text = read(&entry.path())?;
            let mut lines = text.lines();
            let var = lines.next().unwrap_or_default().trim().to_owned();
            if var.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return Err(format!("{}: malformed", entry.path().display()));
            }
            let optional = lines.any(|l| l.trim() == "optional");
            mods.push((name, var, optional));
        }
        mods.sort();
        Ok(mods)
    }

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

    fn seed(&self) -> Result<(), String> {
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
             \x20 - name: {ADMIN}\n\
             \x20   shell: /bin/bash\n\
             \x20   sudo: \"ALL=(ALL) NOPASSWD:ALL\"\n\
             \x20   lock_passwd: true\n\
             \x20   ssh_authorized_keys:\n\
             \x20     - {client}\n\
             \x20 - name: {RUNNER}\n\
             \x20   shell: /bin/bash\n\
             \x20   lock_passwd: true\n\
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
             \x20 - [systemctl, disable, --now, unattended-upgrades.service, apt-daily.timer, apt-daily-upgrade.timer]\n",
            client = client.trim(),
            host_pub = host_pub.trim(),
        );
        let meta = format!(
            "instance-id: {NAME}-{}\nlocal-hostname: {NAME}\n",
            unix_now()
        );
        let net = format!(
            "version: 2\nethernets:\n  mgmt0:\n    match:\n      macaddress: \"{MGMT_MAC}\"\n    \
             set-name: mgmt0\n    dhcp4: true\n    dhcp6: false\n    accept-ra: false\n    \
             link-local: []\n    dhcp-identifier: mac\n"
        );
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

    // ---- network ------------------------------------------------------

    /// (Re)defines the egress filter with the host's current addresses; a
    /// running VM picks the new rules up at once.
    fn define_filter(&self) -> Result<(), String> {
        let gateway = default_gateway()?;
        let host = host_ipv4s()?;
        // libvirt refuses a redefinition without the filter's uuid.
        let uuid = virsh(&["nwfilter-dumpxml", FILTER]).ok().and_then(|x| {
            let rest = x.split("<uuid>").nth(1)?;
            rest.split("</uuid>").next().map(str::to_owned)
        });
        let mut text = egress_filter(&gateway, &host);
        if let Some(uuid) = uuid {
            text = text.replacen(
                "chain='root'>\n",
                &format!("chain='root'>\n  <uuid>{uuid}</uuid>\n"),
                1,
            );
        }
        let xml = self.path(&format!("{FILTER}.xml"));
        write(&xml, &text)?;
        virsh(&["nwfilter-define", &xml.to_string_lossy()]).map(|_| ())
    }

    /// From inside the VM, as root (the filter must hold even then): the
    /// internet answers; the LAN, every host address, the NAT gateway
    /// (beyond its DNS, the one port the VM needs there) and IPv6 do not.
    fn check_network(&self) -> Result<(), String> {
        let lan_gw = host_lan_gateway().unwrap_or_default();
        let mut targets: Vec<String> = host_ipv4s()?;
        if !lan_gw.is_empty() {
            targets.push(lan_gw);
        }
        targets.sort();
        targets.dedup();
        let script = format!(
            "fail=0\n\
             ok() {{ printf '  %-44s %s\\n' \"$1\" \"$2\"; }}\n\
             if getent hosts github.com >/dev/null; then ok 'DNS (github.com)' yes; else ok 'DNS (github.com)' 'NO — expected yes'; fail=1; fi\n\
             if curl -fsS -o /dev/null --max-time 15 https://api.github.com/zen; then ok 'HTTPS api.github.com' yes; else ok 'HTTPS api.github.com' 'NO — expected yes'; fail=1; fi\n\
             for ip in {targets}; do\n\
               for port in 22 53 80 443 7979 8729; do\n\
                 [ \"$ip:$port\" = {gateway}:53 ] && continue\n\
                 if timeout 1 bash -c \"</dev/tcp/$ip/$port\" 2>/dev/null; then ok \"tcp $ip:$port\" 'OPEN — must be blocked'; fail=1; fi\n\
               done\n\
               if ping -c1 -W1 \"$ip\" >/dev/null 2>&1; then ok \"ping $ip\" 'ANSWERS — must be blocked'; fail=1; else ok \"ping $ip\" blocked; fi\n\
             done\n\
             for net in 10.0.0.1 172.16.0.1 100.64.0.1 192.168.1.1; do\n\
               if ping -c1 -W2 $net >/dev/null 2>&1; then ok \"ping $net\" 'ANSWERS — must be blocked'; fail=1; fi\n\
             done\n\
             if ip -6 route get 2001:4860:4860::8888 >/dev/null 2>&1 && ping -6 -c1 -W2 2001:4860:4860::8888 >/dev/null 2>&1; then ok IPv6 'WORKS — must be blocked'; fail=1; else ok IPv6 blocked; fi\n\
             exit $fail\n",
            targets = targets.join(" "),
            gateway = default_gateway()?,
        );
        eprintln!("ci-runner: network from inside {NAME} (as root):");
        self.ssh_root_script(&script).map_err(|_| {
            format!(
                "{NAME} reaches something it must not (or not the internet); see above. \
                 `cargo xtask ci-runner down` until it is fixed"
            )
        })?;
        eprintln!("ci-runner: network ok: internet only");
        Ok(())
    }

    // ---- register -----------------------------------------------------

    fn register(&self) -> Result<(), String> {
        let runners = self.runner_count()?;
        let snapshots = self.snapshots()?;
        if !snapshots.iter().any(|s| s == BASE_SNAPSHOT) {
            return Err(format!(
                "{NAME} has no `base` snapshot: `cargo xtask ci-runner create`"
            ));
        }
        // Registering again starts from `base`: no stale credentials.
        self.revert(BASE_SNAPSHOT)?;
        self.check_network()?;
        eprintln!(
            "\nRegistration token: GitHub → {REPO} → Settings → Actions → Runners → \
             New self-hosted runner → Linux; copy the value after `--token` (valid for 1 hour).\n\
             It registers {runners} runner(s) corerouter-ci-1…{runners} with the label `{LABEL}`; \
             it is not stored anywhere."
        );
        let token = read_secret("token (hidden): ")?;
        if token.len() < 20
            || token.len() > 128
            || !token.chars().all(|c| c.is_ascii_alphanumeric())
        {
            return Err("that does not look like a runner registration token".into());
        }
        let script = format!(
            "set -e\n\
             export ACTIONS_RUNNER_INPUT_TOKEN={token}\n\
             for i in $(seq 1 {runners}); do\n\
               cd /opt/actions-runner/$i\n\
               sudo -u {RUNNER} --preserve-env=ACTIONS_RUNNER_INPUT_TOKEN ./config.sh --unattended \
             --url https://github.com/{REPO} --name {NAME}-$i --labels {LABEL} \
             --work {CACHE}/work-$i --replace >/dev/null\n\
               echo \"registered {NAME}-$i\"\n\
             done\n\
             unset ACTIONS_RUNNER_INPUT_TOKEN\n\
             systemctl enable corerouter-runner@{{1..{runners}}}.service >/dev/null 2>&1\n",
        );
        self.ssh_root_script(&script)?;
        self.snapshot(REGISTERED_SNAPSHOT)?;
        self.up()?;
        std::thread::sleep(Duration::from_secs(5));
        self.status()?;
        eprintln!(
            "\nci-runner: registered. The queue sends batches to it while GitHub shows it online \
             (scripts/land.sh); see docs/ci-runner.md for main and for turning it off."
        );
        Ok(())
    }

    fn runner_count(&self) -> Result<u32, String> {
        self.up()?;
        let out = self.ssh_output("ls -d /opt/actions-runner/[0-9]* 2>/dev/null | wc -l")?;
        let n: u32 = out.trim().parse().unwrap_or(0);
        if n == 0 {
            return Err(format!(
                "{NAME} has no runner installed: `cargo xtask ci-runner create`"
            ));
        }
        Ok(n)
    }

    // ---- status -------------------------------------------------------

    fn status(&self) -> Result<(), String> {
        let Some(state) = self.state()? else {
            println!("{NAME}: not created (`cargo xtask ci-runner create`)");
            return Ok(());
        };
        println!("{NAME}: {state} (dir {})", self.dir.display());
        println!("snapshots: {}", self.snapshots()?.join(", "));
        let filtered = virsh(&["dumpxml", NAME])?.contains(&format!("filter='{FILTER}'"));
        println!(
            "egress filter {FILTER}: {}",
            if filtered { "attached" } else { "MISSING" }
        );
        if state == "running"
            && let Ok(out) = self.ssh_output(&format!(
                "for u in /etc/systemd/system/multi-user.target.wants/corerouter-runner@*.service; do \
                   [ -e \"$u\" ] || continue; n=${{u##*@}}; n=${{n%.service}}; \
                   printf 'runner %s: %s%s\\n' \"$n\" \"$(systemctl is-active corerouter-runner@$n)\" \
                   \"$([ -e {RUN}/busy-$n ] && echo ', in a job')\"; done; \
                 echo \"jobs since the last reset: $(cat {STATE}/jobs-done 2>/dev/null || echo 0)\"; \
                 echo 'last verdicts:'; tail -n 5 {STATE}/jobs.log 2>/dev/null | sed 's/^/  /'; \
                 df -h --output=avail,size {CACHE} | tail -1 | awk '{{print \"cache disk: \" $1 \" free of \" $2}}'"
            ))
        {
            print!("{out}");
        }
        match github_runners() {
            Ok(rows) if rows.is_empty() => println!("GitHub: no runner registered"),
            Ok(rows) => {
                for r in rows {
                    println!(
                        "GitHub: {} {}{}",
                        r.name,
                        r.status,
                        if r.busy { " busy" } else { "" }
                    );
                }
            }
            Err(e) => println!("GitHub: unknown ({e})"),
        }
        Ok(())
    }

    // ---- run ----------------------------------------------------------

    fn run(&self, args: &[String]) -> Result<(), String> {
        let mut rev = "HEAD".to_owned();
        let mut slot = "1".to_owned();
        let mut rest = args;
        while let Some((first, tail)) = rest.split_first() {
            match first.as_str() {
                "--rev" | "--slot" => {
                    let (v, t) = tail
                        .split_first()
                        .ok_or_else(|| format!("{first} needs a value"))?;
                    if first == "--rev" {
                        rev = v.clone();
                    } else {
                        slot = v.clone();
                    }
                    rest = t;
                    continue;
                }
                "--" => {
                    rest = tail;
                    break;
                }
                _ => break,
            }
        }
        if rest.is_empty() {
            return Err(format!("nothing to run\n{HELP}"));
        }
        if !slot.chars().all(|c| c.is_ascii_digit()) || slot.is_empty() {
            return Err("--slot is a number".into());
        }
        let sha = output(Command::new("git").current_dir(&self.root).args([
            "rev-parse",
            "--verify",
            &format!("{rev}^{{commit}}"),
        ]))?
        .trim()
        .to_owned();
        self.up()?;
        let dir = format!("{CACHE}/try/{slot}");
        // The export goes over SSH stdin, as `runner`: no host path, no
        // .git, nothing of the working tree. It lands in a scratch directory
        // and only the files that differ are copied over the slot's tree, as
        // `actions/checkout` does on a kept workspace: a bare `tar -x` stamps
        // every file with the commit's time, older than the last build, and
        // cargo then reuses crates built from the previous commit
        // (**measured**: a stale engine failed to compile).
        let started = Instant::now();
        let mut archive = Command::new("git")
            .current_dir(&self.root)
            .args(["archive", "--format=tar", &sha])
            .stdout(Stdio::piped())
            .spawn()
            .map_err(|e| format!("git archive: {e}"))?;
        let stdout = archive
            .stdout
            .take()
            .ok_or_else(|| "git archive: no stdout".to_owned())?;
        let unpack = self
            .ssh()?
            .arg(format!(
                "sudo -u {RUNNER} bash -c {}",
                shell_quote(&format!(
                    "set -e; rm -rf {dir}.new; mkdir -p {dir}.new {dir}; tar -x -C {dir}.new; \
                     rsync -r --checksum --delete --exclude=/target {dir}.new/ {dir}/; rm -rf {dir}.new"
                ))
            ))
            .stdin(stdout)
            .status()
            .map_err(|e| format!("ssh: {e}"))?;
        let _ = archive.wait();
        if !unpack.success() {
            return Err(format!("could not copy {sha} into {NAME}"));
        }
        let cmd = match rest {
            [one] => one.clone(),
            many => many
                .iter()
                .map(|a| shell_quote(a))
                .collect::<Vec<_>>()
                .join(" "),
        };
        let script = format!(
            "set -a; . {ETC}/runner.env; set +a\n\
             export CARGO_TARGET_DIR={CACHE}/target-try{slot}\n\
             cd {dir} && {cmd}"
        );
        let status = self
            .ssh()?
            .arg(format!("sudo -u {RUNNER} bash -c {}", shell_quote(&script)))
            .stdin(Stdio::null())
            .status()
            .map_err(|e| format!("ssh: {e}"))?;
        eprintln!(
            "ci-runner: {} in {NAME} in {:.1} s, {status}",
            &sha[..sha.len().min(10)],
            started.elapsed().as_secs_f64()
        );
        if status.success() {
            Ok(())
        } else {
            Err(format!("command in {NAME} exited with {status}"))
        }
    }

    // ---- reset --------------------------------------------------------

    fn reset_cmd(&self, args: &[String]) -> Result<(), String> {
        let mut due: Option<u64> = None;
        let mut wipe = false;
        let mut force = false;
        let mut it = args.iter().peekable();
        while let Some(a) = it.next() {
            match a.as_str() {
                "--if-due" => {
                    let n = match it.peek().map(|v| v.parse::<u64>()) {
                        Some(Ok(n)) => {
                            it.next();
                            n
                        }
                        _ => DUE_DEFAULT,
                    };
                    due = Some(n);
                }
                "--wipe-cache" => wipe = true,
                "--force" => force = true,
                other => return Err(format!("reset: unknown option {other}\n{HELP}")),
            }
        }
        if self.state()?.is_none() {
            if due.is_some() {
                return Ok(());
            }
            return Err(format!(
                "{NAME} does not exist: `cargo xtask ci-runner create`"
            ));
        }
        let running = self.state()?.as_deref() == Some("running");
        if let Some(n) = due {
            if !running {
                return Ok(());
            }
            let done: u64 = self
                .ssh_output(&format!("cat {STATE}/jobs-done 2>/dev/null || echo 0"))?
                .trim()
                .parse()
                .unwrap_or(0);
            if done < n {
                println!("ci-runner: {done} of {n} jobs since the last reset; not due");
                return Ok(());
            }
            println!("ci-runner: {done} jobs since the last reset (>= {n}); resetting");
        }
        if running && !force {
            // Stop taking jobs first, then make sure none was running.
            let busy = self.ssh_output(&format!("ls {RUN} 2>/dev/null | grep '^busy-' || true"))?;
            if !busy.trim().is_empty() {
                let msg = format!(
                    "a job is running ({}); try again later, or --force",
                    busy.trim()
                );
                return if due.is_some() {
                    println!("ci-runner: {msg}");
                    Ok(())
                } else {
                    Err(msg)
                };
            }
            self.ssh_output("sudo systemctl stop 'corerouter-runner@*.service'")?;
            let busy = self.ssh_output(&format!("ls {RUN} 2>/dev/null | grep '^busy-' || true"))?;
            if !busy.trim().is_empty() {
                let _ = self.ssh_output("sudo systemctl start --all 'corerouter-runner@*.service'");
                return Err(format!(
                    "a job started while stopping ({}); runners restarted, try again later",
                    busy.trim()
                ));
            }
        }
        if wipe && running {
            self.ssh_output(&format!(
                "sudo rm -rf {CACHE}/target-* {CACHE}/try {CACHE}/work-*"
            ))?;
            println!("ci-runner: build caches wiped");
        }
        let snap = if self.snapshots()?.iter().any(|s| s == REGISTERED_SNAPSHOT) {
            REGISTERED_SNAPSHOT
        } else {
            BASE_SNAPSHOT
        };
        self.define_filter()?;
        self.revert(snap)?;
        if wipe && !running {
            self.ssh_output(&format!(
                "sudo rm -rf {CACHE}/target-* {CACHE}/try {CACHE}/work-*"
            ))?;
            println!("ci-runner: build caches wiped");
        }
        Ok(())
    }

    // ---- lifecycle ----------------------------------------------------

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
            .ok_or_else(|| format!("{NAME} does not exist: `cargo xtask ci-runner create`"))
    }

    fn up(&self) -> Result<(), String> {
        if self.require()? != "running" {
            // Host addresses change (DHCP, VPN): refresh before booting.
            self.define_filter()?;
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
        let deadline = Instant::now() + Duration::from_secs(120);
        while Instant::now() < deadline {
            if self.state()?.as_deref() == Some("shut off") {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        eprintln!("ci-runner: no clean shutdown in 120 s; powering off");
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
        let _ = virsh(&["nwfilter-undefine", FILTER]);
        for f in [
            format!("{NAME}.qcow2"),
            format!("{NAME}-cache.qcow2"),
            "seed.iso".into(),
            format!("{NAME}.xml"),
            format!("{FILTER}.xml"),
        ] {
            let _ = std::fs::remove_file(self.path(&f));
        }
        eprintln!(
            "ci-runner: {NAME} destroyed (base/ and the key stay). The runners are still \
             listed on GitHub until `cargo xtask ci-runner unregister --yes`"
        );
        Ok(())
    }

    fn system_disk(&self) -> PathBuf {
        self.path(&format!("{NAME}.qcow2"))
    }

    /// Internal snapshots of the system disk (`qemu-img snapshot -l`).
    fn snapshots(&self) -> Result<Vec<String>, String> {
        let out = output(Command::new("qemu-img").args([
            "snapshot",
            "-U",
            "-l",
            &self.system_disk().to_string_lossy(),
        ]))?;
        Ok(parse_snapshots(&out))
    }

    /// Offline internal snapshot of the system disk only, with `qemu-img`:
    /// libvirt's internal snapshots take every disk, and the cache disk
    /// (`vdb`) must keep living across resets.
    fn snapshot(&self, name: &str) -> Result<(), String> {
        check_snapshot_name(name)?;
        self.down()?;
        let disk = self.system_disk();
        if self.snapshots()?.iter().any(|s| s == name) {
            run_ok(
                Command::new("qemu-img")
                    .args(["snapshot", "-d", name])
                    .arg(&disk),
            )?;
        }
        run_ok(
            Command::new("qemu-img")
                .args(["snapshot", "-c", name])
                .arg(&disk),
        )?;
        eprintln!("ci-runner: snapshot `{name}` taken");
        Ok(())
    }

    /// Back to a snapshot of the system disk and boot.
    fn revert(&self, name: &str) -> Result<(), String> {
        check_snapshot_name(name)?;
        let started = Instant::now();
        if self.require()? == "running" {
            self.close_master();
            virsh(&["destroy", NAME])?;
        }
        run_ok(
            Command::new("qemu-img")
                .args(["snapshot", "-a", name])
                .arg(self.system_disk()),
        )?;
        self.up()?;
        self.apply_modules()?;
        eprintln!(
            "ci-runner: back to `{name}` and booted in {:.1} s",
            started.elapsed().as_secs_f64()
        );
        Ok(())
    }

    /// Loads the modules `ci/kernel-modules/` lists now (a new one since
    /// `create` included) and keeps them for the next boots: the jobs cannot
    /// load modules (no sudo), and the setup action fails without them.
    fn apply_modules(&self) -> Result<(), String> {
        let mods = self.kernel_modules()?;
        let load: String = mods.iter().map(|(m, _, _)| format!("{m}\n")).collect();
        let probe: String = mods
            .iter()
            .map(|(m, _, optional)| {
                if *optional {
                    format!("modprobe {m} 2>/dev/null || echo 'ci-runner: optional module {m} not available'\n")
                } else {
                    format!("modprobe {m} || {{ echo 'ci-runner: module {m} missing'; fail=1; }}\n")
                }
            })
            .collect();
        self.ssh_root_script(&format!(
            "fail=0\ncat > /etc/modules-load.d/corerouter-ci.conf <<'EOF'\n{load}EOF\n{probe}exit $fail\n"
        ))
    }

    // ---- ssh ----------------------------------------------------------

    fn address(&self) -> Result<Option<String>, String> {
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
            .arg(format!("{ADMIN}@{ip}"));
        c
    }

    fn ssh(&self) -> Result<Command, String> {
        let ip = self
            .address()?
            .ok_or_else(|| format!("{NAME} has no address yet: `cargo xtask ci-runner up`"))?;
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

    /// A bash script as root over stdin (never in an argument: `register`
    /// sends the token this way), output streamed.
    fn ssh_root_script(&self, script: &str) -> Result<(), String> {
        let mut child = self
            .ssh()?
            .args(["sudo", "bash", "-s"])
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| format!("ssh: {e}"))?;
        if let Some(mut stdin) = child.stdin.take() {
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

    fn put(&self, from: &Path, to: &str) -> Result<(), String> {
        let file = std::fs::File::open(from).map_err(|e| format!("{}: {e}", from.display()))?;
        let status = self
            .ssh()?
            .arg(format!("cat > {}", shell_quote(to)))
            .stdin(file)
            .status()
            .map_err(|e| format!("ssh: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("could not copy {} to {NAME}:{to}", from.display()))
        }
    }

    fn ssh_interactive(&self, args: &[String]) -> Result<(), String> {
        self.up()?;
        let mut c = self.ssh()?;
        if args.is_empty() {
            c.arg("-t");
        } else {
            // One argument is a shell line (`ssh 'a | b'`), several are
            // quoted one by one, as in `vm-lab ssh`.
            c.arg(match args {
                [one] => one.clone(),
                many => many
                    .iter()
                    .map(|a| shell_quote(a))
                    .collect::<Vec<_>>()
                    .join(" "),
            });
        }
        let status = c.status().map_err(|e| format!("ssh: {e}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("command in {NAME} exited with {status}"))
        }
    }
}

fn domain_xml(spec: &Spec, system: &Path, cache: &Path, seed: &Path) -> String {
    // `host-model` and no wires: see vm_lab's domain for why not
    // `host-passthrough`. The filter is applied by libvirt on the host's
    // side of the NIC.
    format!(
        "<domain type='kvm'>\n  <name>{NAME}</name>\n  \
         <description>CoreRouter self-hosted CI runner (cargo xtask ci-runner, docs/ci-runner.md)</description>\n  \
         <memory unit='MiB'>{mem}</memory>\n  <vcpu>{cpus}</vcpu>\n  \
         <os><type arch='x86_64' machine='q35'>hvm</type><boot dev='hd'/></os>\n  \
         <features><acpi/><apic/></features>\n  \
         <cpu mode='host-model' check='partial'/>\n  \
         <clock offset='utc'/>\n  <on_poweroff>destroy</on_poweroff>\n  \
         <on_reboot>restart</on_reboot>\n  <on_crash>destroy</on_crash>\n  <devices>\n    \
         <disk type='file' device='disk'>\n      \
         <driver name='qemu' type='qcow2' discard='unmap'/>\n      \
         <source file='{system}'/>\n      <target dev='vda' bus='virtio'/>\n    </disk>\n    \
         <disk type='file' device='disk'>\n      \
         <driver name='qemu' type='qcow2' discard='unmap'/>\n      \
         <source file='{cache}'/>\n      <target dev='vdb' bus='virtio'/>\n      \
         <serial>corerouter-ci-cache</serial>\n    </disk>\n    \
         <disk type='file' device='cdrom'>\n      <driver name='qemu' type='raw'/>\n      \
         <source file='{seed}'/>\n      <target dev='sda' bus='sata'/>\n      <readonly/>\n    \
         </disk>\n    \
         <interface type='network'>\n      <source network='default'/>\n      \
         <mac address='{MGMT_MAC}'/>\n      <model type='virtio'/>\n      \
         <filterref filter='{FILTER}'/>\n    </interface>\n    \
         <serial type='pty'/>\n    <console type='pty'/>\n    \
         <channel type='unix'><target type='virtio' name='org.qemu.guest_agent.0'/></channel>\n    \
         <rng model='virtio'><backend model='random'>/dev/urandom</backend></rng>\n  \
         </devices>\n</domain>\n",
        mem = spec.memory_mib,
        cpus = spec.cpus,
        system = system.display(),
        cache = cache.display(),
        seed = seed.display(),
    )
}

/// The VM's egress rules, applied by libvirt on the host (ebtables, at the
/// bridge port: neither root in the VM nor `br_netfilter` matters). DNS and
/// DHCP to the NAT gateway and the replies of the host's SSH pass; private, shared, link-local and multicast
/// ranges, every address of the host, and all IPv6 are dropped; the rest
/// (the internet, through NAT) passes.
fn egress_filter(gateway: &str, host: &[String]) -> String {
    let mut rules = String::new();
    let mut rule = |action: &str, prio: u32, body: &str| {
        rules.push_str(&format!(
            "  <rule action='{action}' direction='out' priority='{prio}'>\n    {body}\n  </rule>\n"
        ));
    };
    for proto in ["udp", "tcp"] {
        rule(
            "accept",
            100,
            &format!("<ip dstipaddr='{gateway}' protocol='{proto}' dstportstart='53'/>"),
        );
    }
    // DHCP: the discover goes to the broadcast (inside 224/3, dropped
    // below), the renewal to the gateway.
    for dst in [gateway, "255.255.255.255"] {
        rule(
            "accept",
            100,
            &format!("<ip dstipaddr='{dst}' protocol='udp' srcportstart='68' dstportstart='67'/>"),
        );
    }
    // The replies of the host's SSH. ebtables has no connection state (and
    // the host has no `br_netfilter` for iptables' physdev match), so this
    // is by port; only root in the VM can bind port 22, and jobs are not root.
    rule(
        "accept",
        100,
        &format!("<ip dstipaddr='{gateway}' protocol='tcp' srcportstart='22'/>"),
    );
    let mut drops: Vec<(String, u8)> = [
        ("10.0.0.0", 8),
        ("172.16.0.0", 12),
        ("192.168.0.0", 16),
        ("100.64.0.0", 10),
        ("169.254.0.0", 16),
        ("127.0.0.0", 8),
        ("0.0.0.0", 8),
        ("224.0.0.0", 3),
    ]
    .iter()
    .map(|(a, m)| ((*a).to_owned(), *m))
    .collect();
    for ip in host {
        drops.push((ip.clone(), 32));
    }
    for (addr, mask) in drops {
        rule(
            "drop",
            200,
            &format!("<ip dstipaddr='{addr}' dstipmask='{mask}'/>"),
        );
    }
    rule("drop", 200, "<ipv6/>");
    format!(
        "<filter name='{FILTER}' chain='root'>\n  \
         <!-- cargo xtask ci-runner (docs/ci-runner.md); regenerated on create/up/reset -->\n{rules}</filter>\n"
    )
}

/// The NAT gateway of libvirt's `default` network.
fn default_gateway() -> Result<String, String> {
    let xml = virsh(&["net-dumpxml", "default"])?;
    xml.split("<ip address='")
        .nth(1)
        .and_then(|s| s.split('\'').next())
        .map(str::to_owned)
        .ok_or_else(|| "libvirt network `default` has no IPv4 address".to_owned())
}

/// Every IPv4 of the host except loopback (`ip -o -4 addr`).
fn host_ipv4s() -> Result<Vec<String>, String> {
    Ok(parse_ipv4s(&output(
        Command::new("ip").args(["-o", "-4", "addr", "show"]),
    )?))
}

fn parse_ipv4s(text: &str) -> Vec<String> {
    let mut out: Vec<String> = text
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            f.find(|w| *w == "inet")?;
            let ip = f.next()?.split('/').next()?.to_owned();
            (!ip.starts_with("127.")).then_some(ip)
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The host's own default gateway (the user's router).
fn host_lan_gateway() -> Option<String> {
    let out = output(Command::new("ip").args(["-4", "route", "show", "default"])).ok()?;
    let mut f = out.split_whitespace();
    f.find(|w| *w == "via")?;
    f.next().map(str::to_owned)
}

/// Reads a line from the terminal with echo off.
fn read_secret(prompt: &str) -> Result<String, String> {
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|e| format!("needs a terminal (/dev/tty: {e}); run it in yours"))?;
    let stty = |arg: &str| {
        Command::new("stty")
            .arg(arg)
            .stdin(
                tty.try_clone()
                    .map(Stdio::from)
                    .unwrap_or_else(|_| Stdio::null()),
            )
            .status()
    };
    eprint!("{prompt}");
    let _ = stty("-echo");
    let mut line = String::new();
    let res = std::io::BufRead::read_line(&mut std::io::BufReader::new(&tty), &mut line);
    let _ = stty("echo");
    eprintln!();
    res.map_err(|e| format!("/dev/tty: {e}"))?;
    Ok(line.trim().to_owned())
}

#[derive(Debug, PartialEq)]
struct GhRunner {
    id: u64,
    name: String,
    status: String,
    busy: bool,
}

/// This VM's runners as GitHub sees them (needs the owner's `gh`).
fn github_runners() -> Result<Vec<GhRunner>, String> {
    let out = output(Command::new("gh").args([
        "api",
        &format!("repos/{REPO}/actions/runners"),
        "--jq",
        ".runners[] | \"\\(.id) \\(.name) \\(.status) \\(.busy)\"",
    ]))?;
    Ok(parse_runners(&out))
}

/// Names from `qemu-img snapshot -l` (rows after the header: ID, TAG, …).
fn parse_snapshots(text: &str) -> Vec<String> {
    text.lines()
        .skip_while(|l| !l.starts_with("ID"))
        .skip(1)
        .filter_map(|l| l.split_whitespace().nth(1).map(str::to_owned))
        .collect()
}

fn parse_runners(text: &str) -> Vec<GhRunner> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let id = f.next()?.parse().ok()?;
            let name = f.next()?.to_owned();
            let status = f.next()?.to_owned();
            let busy = f.next()? == "true";
            name.starts_with(&format!("{NAME}-")).then_some(GhRunner {
                id,
                name,
                status,
                busy,
            })
        })
        .collect()
}

fn unregister(args: &[String]) -> Result<(), String> {
    let yes = args.iter().any(|a| a == "--yes");
    let rows = github_runners()?;
    if rows.is_empty() {
        println!("no {NAME}-* runner on GitHub");
        return Ok(());
    }
    for r in &rows {
        if yes {
            run_ok(Command::new("gh").args([
                "api",
                "-X",
                "DELETE",
                &format!("repos/{REPO}/actions/runners/{}", r.id),
            ]))?;
            println!("removed {} (id {})", r.name, r.id);
        } else {
            println!("would remove {} (id {}, {})", r.name, r.id, r.status);
        }
    }
    if !yes {
        println!("run `cargo xtask ci-runner unregister --yes` to remove them");
    }
    Ok(())
}

/// Provisioning, as root, after cloud-init: the cache disk, kernel modules
/// and sysctls the tests need, Rust and nextest for `runner`, the runner
/// copies, the hooks and the systemd unit.
fn provision_script(spec: &Spec, modules: &[(String, String, bool)]) -> String {
    let load: String = modules.iter().map(|(m, _, _)| format!("{m}\n")).collect();
    let runners = spec.runners;
    format!(
        "set -euo pipefail\n\
         # Cache disk (vdb): build caches, kept across resets.\n\
         dev=/dev/disk/by-id/virtio-corerouter-ci-cache\n\
         blkid \"$dev\" >/dev/null 2>&1 || mkfs.ext4 -q -L cr-ci-cache \"$dev\"\n\
         mkdir -p {CACHE}\n\
         grep -q cr-ci-cache /etc/fstab || echo 'LABEL=cr-ci-cache {CACHE} ext4 defaults,noatime 0 2' >> /etc/fstab\n\
         mountpoint -q {CACHE} || mount {CACHE}\n\
         chown {RUNNER}:{RUNNER} {CACHE}\n\
         # Swap on the cache disk: peaks of 3 jobs at once (the `frames`\n\
         # bench alone reached 6.4 GB RSS while the others linked: OOM in 16 GiB,\n\
         # **measured**); the host has no RAM to spare for a bigger VM.\n\
         if [ ! -f {CACHE}/swapfile ]; then fallocate -l 16G {CACHE}/swapfile; chmod 600 {CACHE}/swapfile; mkswap -q {CACHE}/swapfile; fi\n\
         grep -q '{CACHE}/swapfile' /etc/fstab || echo '{CACHE}/swapfile none swap sw,nofail 0 0' >> /etc/fstab\n\
         swapon --show=NAME --noheadings | grep -q swapfile || swapon {CACHE}/swapfile\n\
         # The journal, as on GitHub's runners (the oslog tests read this machine's).\n\
         usermod -aG systemd-journal {RUNNER}\n\
         # Kernel: modules a user namespace cannot load, and unprivileged\n\
         # user namespaces (the netns tests).\n\
         cat > /etc/modules-load.d/corerouter-ci.conf <<'EOF'\n{load}EOF\n\
         echo 'kernel.apparmor_restrict_unprivileged_userns = 0' > /etc/sysctl.d/60-corerouter-ci.conf\n\
         # State dirs: hooks write here as {RUNNER}.\n\
         install -d -o {RUNNER} -g {RUNNER} -m 0755 {STATE}\n\
         echo 'd {RUN} 0755 {RUNNER} {RUNNER} -' > /etc/tmpfiles.d/corerouter-ci.conf\n\
         systemd-tmpfiles --create /etc/tmpfiles.d/corerouter-ci.conf\n\
         # Rust for {RUNNER} (rust-toolchain.toml's components) and nextest.\n\
         cp /tmp/rust-toolchain.toml /home/{RUNNER}/rust-toolchain.toml\n\
         chown {RUNNER}:{RUNNER} /home/{RUNNER}/rust-toolchain.toml\n\
         sudo -u {RUNNER} -H bash -s <<'EOS'\n\
         set -e\n\
         cd ~\n\
         [ -x ~/.cargo/bin/rustup ] || curl --proto =https --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y -q --profile minimal --default-toolchain none\n\
         . ~/.cargo/env\n\
         rustup toolchain install >/dev/null\n\
         command -v cargo-nextest >/dev/null || cargo install --locked --quiet cargo-nextest\n\
         cargo --version; cargo nextest --version | head -1\n\
         EOS\n\
         # The runners: one copy each, owned by {RUNNER} (it updates itself).\n\
         for i in $(seq 1 {runners}); do\n\
           install -d -o {RUNNER} -g {RUNNER} /opt/actions-runner/$i\n\
           sudo -u {RUNNER} tar -xzf /tmp/actions-runner.tar.gz -C /opt/actions-runner/$i\n\
         done\n\
         /opt/actions-runner/1/bin/installdependencies.sh >/dev/null\n\
         rm -f /tmp/actions-runner.tar.gz\n\
         # Hooks and environment: root's, outside the runner's reach.\n\
         install -d -o root -g root -m 0755 {ETC}\n\
         cat > {ETC}/job-started.sh <<'EOF'\n{started}EOF\n\
         cat > {ETC}/job-completed.sh <<'EOF'\n{completed}EOF\n\
         chmod 0755 {ETC}/job-started.sh {ETC}/job-completed.sh\n\
         cat > {ETC}/runner.env <<'EOF'\n{env}EOF\n\
         cat > /etc/systemd/system/corerouter-runner@.service <<'EOF'\n{unit}EOF\n\
         systemctl daemon-reload\n\
         echo provisioned\n",
        started = JOB_STARTED.replace("@REPO@", REPO),
        completed = JOB_COMPLETED,
        env = runner_env(),
        unit = UNIT,
    )
}

/// The environment of every job (and of `run`): the same as the GitHub
/// runners' plus the slots and caches of this VM.
fn runner_env() -> String {
    format!(
        "PATH=/home/{RUNNER}/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n\
         HOME=/home/{RUNNER}\n\
         CARGO_INCREMENTAL=0\n\
         COREROUTER_CI_SLOTS=3\n\
         XDG_RUNTIME_DIR={RUN}\n\
         ACTIONS_RUNNER_HOOK_JOB_STARTED={ETC}/job-started.sh\n\
         ACTIONS_RUNNER_HOOK_JOB_COMPLETED={ETC}/job-completed.sh\n"
    )
}

/// One runner instance: `corerouter-runner@<n>`.
const UNIT: &str = "# cargo xtask ci-runner (docs/ci-runner.md)
[Unit]
Description=GitHub Actions runner %i of corerouter-ci
After=network-online.target
Wants=network-online.target
ConditionPathExists=/opt/actions-runner/%i/.runner

[Service]
User=runner
WorkingDirectory=/opt/actions-runner/%i
EnvironmentFile=/etc/corerouter-ci/runner.env
Environment=CR_CI_RUNNER=%i
Environment=CARGO_TARGET_DIR=/var/cache/corerouter-ci/target-%i
ExecStart=/opt/actions-runner/%i/run.sh
KillMode=process
KillSignal=SIGTERM
TimeoutStopSec=60
Restart=always
RestartSec=10
NoNewPrivileges=yes
ProtectSystem=full
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
";

/// Runs before every job (`ACTIONS_RUNNER_HOOK_JOB_STARTED`, set in the
/// unit, root-owned): a non-zero exit fails the job before its first step.
/// The `GITHUB_*` variables come from the runner, not from the workflow, so
/// a job cannot fake them. Anything not trusted is refused: a fork's pull
/// request that edits the workflow to `runs-on: [self-hosted]` dies here.
const JOB_STARTED: &str = r#"#!/bin/bash
# corerouter-ci: only trusted code (docs/ci-runner.md). Fails closed.
state=${CR_CI_STATE:-/var/lib/corerouter-ci}
run=${CR_CI_RUN:-/run/corerouter-ci}
want=@REPO@
event=${GITHUB_EVENT_NAME:-} ref=${GITHUB_REF:-} repo=${GITHUB_REPOSITORY:-}
verdict=refused
if [ "$repo" = "$want" ]; then
  case "$event:$ref" in
    push:refs/heads/main) verdict=ok ;;
    workflow_dispatch:refs/heads/queue/*) verdict=ok ;;
  esac
fi
printf '%s %s runner=%s event=%s ref=%s repo=%s run=%s actor=%s\n' "$(date -u +%FT%TZ)" \
  "$verdict" "${CR_CI_RUNNER:-?}" "$event" "$ref" "$repo" "${GITHUB_RUN_ID:-}" \
  "${GITHUB_ACTOR:-}" >> "$state/jobs.log" 2>/dev/null
if [ "$verdict" != ok ]; then
  echo "::error::corerouter-ci recusa este job: só push na main e workflow_dispatch em queue/* de $want (event=$event ref=$ref repo=$repo)"
  exit 1
fi
: > "$run/busy-${CR_CI_RUNNER:-0}" 2>/dev/null
exit 0
"#;

/// After every job: clears the busy mark and counts the job for
/// `reset --if-due`.
const JOB_COMPLETED: &str = r#"#!/bin/bash
state=${CR_CI_STATE:-/var/lib/corerouter-ci}
run=${CR_CI_RUN:-/run/corerouter-ci}
rm -f "$run/busy-${CR_CI_RUNNER:-0}"
n=$(cat "$state/jobs-done" 2>/dev/null || echo 0)
case "$n" in ''|*[!0-9]*) n=0 ;; esac
echo $((n + 1)) > "$state/jobs-done"
exit 0
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d =
            std::env::temp_dir().join(format!("xtask-ci-runner-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Runs the job-started hook with only the given variables.
    fn started(vars: &[(&str, &str)]) -> (bool, String, PathBuf) {
        let d = scratch("hook");
        let hook = d.join("job-started.sh");
        std::fs::write(&hook, JOB_STARTED.replace("@REPO@", REPO)).unwrap();
        let mut c = Command::new("bash");
        c.arg(&hook)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("CR_CI_STATE", &d)
            .env("CR_CI_RUN", &d)
            .env("CR_CI_RUNNER", "2");
        for (k, v) in vars {
            c.env(k, v);
        }
        let out = c.output().unwrap();
        (
            out.status.success(),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            d,
        )
    }

    #[test]
    fn the_hook_runs_only_the_queue_and_main() {
        for (event, ref_) in [
            ("workflow_dispatch", "refs/heads/queue/batch-1793305057482"),
            ("push", "refs/heads/main"),
        ] {
            let (ok, _, d) = started(&[
                ("GITHUB_EVENT_NAME", event),
                ("GITHUB_REF", ref_),
                ("GITHUB_REPOSITORY", REPO),
            ]);
            assert!(ok, "{event} {ref_}");
            assert!(d.join("busy-2").exists());
            let log = std::fs::read_to_string(d.join("jobs.log")).unwrap();
            assert!(log.contains(" ok runner=2 "), "{log}");
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn the_hook_refuses_everything_else_and_fails_closed() {
        let cases: &[&[(&str, &str)]] = &[
            // A fork's pull request that edited runs-on.
            &[
                ("GITHUB_EVENT_NAME", "pull_request"),
                ("GITHUB_REF", "refs/pull/9/merge"),
                ("GITHUB_REPOSITORY", REPO),
            ],
            // pull_request_target runs on the base ref: refused by event.
            &[
                ("GITHUB_EVENT_NAME", "pull_request_target"),
                ("GITHUB_REF", "refs/heads/main"),
                ("GITHUB_REPOSITORY", REPO),
            ],
            // A dispatch on any other branch.
            &[
                ("GITHUB_EVENT_NAME", "workflow_dispatch"),
                ("GITHUB_REF", "refs/heads/stream/x"),
                ("GITHUB_REPOSITORY", REPO),
            ],
            // A tag that looks like the queue.
            &[
                ("GITHUB_EVENT_NAME", "workflow_dispatch"),
                ("GITHUB_REF", "refs/tags/queue/x"),
                ("GITHUB_REPOSITORY", REPO),
            ],
            // Push to a branch that is not main.
            &[
                ("GITHUB_EVENT_NAME", "push"),
                ("GITHUB_REF", "refs/heads/main2"),
                ("GITHUB_REPOSITORY", REPO),
            ],
            // Another repository (a fork's own workflows).
            &[
                ("GITHUB_EVENT_NAME", "push"),
                ("GITHUB_REF", "refs/heads/main"),
                ("GITHUB_REPOSITORY", "someone/CoreRouter"),
            ],
            &[
                ("GITHUB_EVENT_NAME", "schedule"),
                ("GITHUB_REPOSITORY", REPO),
            ],
            // Nothing set: fail closed.
            &[],
        ];
        for vars in cases {
            let (ok, stdout, d) = started(vars);
            assert!(!ok, "{vars:?} must be refused");
            assert!(stdout.contains("::error::corerouter-ci recusa"), "{stdout}");
            assert!(!d.join("busy-2").exists());
            std::fs::remove_dir_all(d).unwrap();
        }
    }

    #[test]
    fn the_completed_hook_counts_jobs() {
        let d = scratch("done");
        let hook = d.join("job-completed.sh");
        std::fs::write(&hook, JOB_COMPLETED).unwrap();
        std::fs::write(d.join("busy-1"), "").unwrap();
        std::fs::write(d.join("jobs-done"), "garbage").unwrap();
        for want in ["1", "2"] {
            let st = Command::new("bash")
                .arg(&hook)
                .env("CR_CI_STATE", &d)
                .env("CR_CI_RUN", &d)
                .env("CR_CI_RUNNER", "1")
                .status()
                .unwrap();
            assert!(st.success());
            assert_eq!(
                std::fs::read_to_string(d.join("jobs-done")).unwrap().trim(),
                want
            );
        }
        assert!(!d.join("busy-1").exists());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn the_filter_lets_dns_through_and_drops_lan_host_and_ipv6() {
        let host = vec!["192.168.0.180".to_owned(), "54.232.189.113".to_owned()];
        let xml = egress_filter("192.168.122.1", &host);
        assert!(xml.contains(&format!("<filter name='{FILTER}' chain='root'>")));
        assert!(xml.contains(
            "<rule action='accept' direction='out' priority='100'>\n    \
             <ip dstipaddr='192.168.122.1' protocol='udp' dstportstart='53'/>"
        ));
        for drop in [
            "<ip dstipaddr='192.168.0.0' dstipmask='16'/>",
            "<ip dstipaddr='10.0.0.0' dstipmask='8'/>",
            "<ip dstipaddr='172.16.0.0' dstipmask='12'/>",
            // A public address the host owns (on lo here) is the host too.
            "<ip dstipaddr='54.232.189.113' dstipmask='32'/>",
            "<ipv6/>",
        ] {
            let at = xml
                .find(drop)
                .unwrap_or_else(|| panic!("{drop} missing:\n{xml}"));
            assert!(
                xml[..at].ends_with("<rule action='drop' direction='out' priority='200'>\n    ")
            );
        }
        assert!(xml.contains(
            "<ip dstipaddr='255.255.255.255' protocol='udp' srcportstart='68' dstportstart='67'/>"
        ));
        // Accepts must win: lower priority runs first.
        assert!(!xml.contains("action='accept' direction='out' priority='200'"));
    }

    #[test]
    fn host_addresses_parse_without_loopback() {
        let text = "1: lo    inet 127.0.0.1/8 scope host lo\\       valid_lft forever\n\
                    1: lo    inet 54.232.189.113/32 scope global lo\n\
                    3: wlp195s0    inet 192.168.0.180/24 brd 192.168.0.255 scope global wlp195s0\n\
                    5: virbr0    inet 192.168.122.1/24 brd 192.168.122.255 scope global virbr0\n";
        assert_eq!(
            parse_ipv4s(text),
            vec!["192.168.0.180", "192.168.122.1", "54.232.189.113"]
        );
    }

    #[test]
    fn github_rows_keep_only_this_vm() {
        let rows = parse_runners(
            "11 corerouter-ci-1 online false\n12 corerouter-ci-2 offline true\n13 other online false\n",
        );
        assert_eq!(
            rows,
            vec![
                GhRunner {
                    id: 11,
                    name: "corerouter-ci-1".into(),
                    status: "online".into(),
                    busy: false
                },
                GhRunner {
                    id: 12,
                    name: "corerouter-ci-2".into(),
                    status: "offline".into(),
                    busy: true
                },
            ]
        );
    }

    #[test]
    fn snapshot_names_come_from_qemu_img() {
        let text = "Snapshot list:\n\
                    ID        TAG               VM_SIZE                DATE        VM_CLOCK     ICOUNT\n\
                    1         base                  0 B 2026-10-29 18:55:01  0000:00:00.000          0\n\
                    2         registered            0 B 2026-10-29 19:20:11  0000:00:00.000          0\n";
        assert_eq!(parse_snapshots(text), vec!["base", "registered"]);
        assert!(parse_snapshots("").is_empty());
    }

    #[test]
    fn spec_flags_are_checked() {
        let s = |a: &[&str]| parse_spec(&a.iter().map(|x| (*x).to_owned()).collect::<Vec<_>>());
        assert_eq!(s(&[]).unwrap().cpus, 16);
        assert_eq!(s(&["--runners", "4", "--cpus", "12"]).unwrap().runners, 4);
        assert!(s(&["--cpus", "64"]).is_err());
        assert!(s(&["--runners"]).is_err());
        assert!(s(&["--bogus", "1"]).is_err());
    }

    #[test]
    fn the_unit_and_env_keep_hooks_out_of_the_jobs_reach() {
        let env = runner_env();
        assert!(env.contains("ACTIONS_RUNNER_HOOK_JOB_STARTED=/etc/corerouter-ci/job-started.sh"));
        assert!(UNIT.contains("EnvironmentFile=/etc/corerouter-ci/runner.env"));
        assert!(UNIT.contains("User=runner"));
        assert!(UNIT.contains("NoNewPrivileges=yes"));
        let p = provision_script(
            &parse_spec(&[]).unwrap(),
            &[("vrf".into(), "COREROUTER_REQUIRE_VRF".into(), false)],
        );
        assert!(p.contains("install -d -o root -g root -m 0755 /etc/corerouter-ci"));
        assert!(p.contains("\nvrf\nEOF"));
        assert!(!p.contains("@REPO@"));
    }
}

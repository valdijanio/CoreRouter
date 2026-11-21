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

mod quiet;

const URI: &str = "qemu:///system";
const IMAGE: &str = "noble-server-cloudimg-amd64.img";
const IMAGE_URL: &str = "https://cloud-images.ubuntu.com/noble/current/";
const MAX_WIRES: u32 = 4;
/// `0` turns off the quieting of `run --perf` (G0.26d), like `--no-quiet`.
const QUIET_VAR: &str = "COREROUTER_VM_QUIET";
/// Picks the VM for every subcommand (`1`, `2`, `lab`, `lab2` or the full
/// name), like `--vm`; `--vm` wins.
const VM_VAR: &str = "COREROUTER_VM_LAB";

/// One lab VM (G0.26c): what differs between them. Each has its own disk,
/// seed, SSH keys, snapshots, host locks and, inside it, its own round lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Vm {
    /// What `--vm` takes.
    num: u8,
    name: &'static str,
    /// Its files under `vm/`: `None` for VM 1, whose files stay where they
    /// were before G0.26c (`vm/corerouter-lab.qcow2`, `vm/id_ed25519`…), so
    /// an older `vm_lab.rs` in another worktree still finds them.
    subdir: Option<&'static str>,
    /// The management NIC's MAC: how `domifaddr` finds the VM's address.
    mgmt_mac: &'static str,
    /// The wires' MACs are `<prefix>:<nn>`.
    wire_mac_prefix: &'static str,
    /// UDP ports on 127.0.0.1 behind the wires (two per NIC pair).
    wire_port_base: u16,
    /// `create` defaults.
    cpus: u32,
    memory_mib: u32,
    disk_gib: u32,
    /// Host CPUs (`cputune`): vCPU i runs on `vcpu_cpus[i % len]`, QEMU's
    /// own threads (I/O, emulator) on `emulator_cpus`. See `docs/vm-lab.md`,
    /// "CPUs por VM".
    vcpu_cpus: &'static [u32],
    emulator_cpus: &'static str,
    /// For `status` and messages.
    role: &'static str,
}

/// VM 1 owns the second CCD (cores 8–15, one vCPU per physical core, its
/// QEMU threads on their SMT siblings 24–31): no other VM runs there, so a
/// measurement is not shared with anyone else's guest. VM 2 and the CI
/// runner share the first CCD (cores 0–7): functional tests only.
const VMS: [Vm; 2] = [
    Vm {
        num: 1,
        name: "corerouter-lab",
        subdir: None,
        mgmt_mac: "52:54:00:c0:72:01",
        wire_mac_prefix: "52:54:00:c0:73",
        wire_port_base: 47_210,
        cpus: 8,
        memory_mib: 16_384,
        disk_gib: 40,
        vcpu_cpus: &[8, 9, 10, 11, 12, 13, 14, 15],
        emulator_cpus: "24-31",
        role: "performance measurements (`run --perf`)",
    },
    Vm {
        num: 2,
        name: "corerouter-lab2",
        subdir: Some("corerouter-lab2"),
        mgmt_mac: "52:54:00:c0:72:02",
        wire_mac_prefix: "52:54:00:c0:74",
        wire_port_base: 47_230,
        cpus: 4,
        // 6 GiB, not 8: the host had 22.7 GB available and 19.5 GB of swap
        // in use when it was made (**measured**, 2026-11-20).
        memory_mib: 6_144,
        disk_gib: 30,
        vcpu_cpus: &[4, 5, 6, 7],
        emulator_cpus: "20-23",
        role: "functional tests (`run` picks it first)",
    },
];

/// The CI runner (`corerouter-ci`, `xtask/src/ci_runner.rs`): 16 vCPUs on
/// the first CCD, both threads of each core, never on VM 1's CCD.
pub(crate) const CI_VCPU_CPUS: &[u32] = &[0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23];
pub(crate) const CI_EMULATOR_CPUS: &str = "0-7,16-23";
const CI_NAME: &str = "corerouter-ci";

impl Vm {
    /// `1`, `2`, `lab`, `lab2`, `corerouter-lab2`.
    fn parse(text: &str) -> Result<Vm, String> {
        let t = text.trim();
        VMS.iter()
            .find(|v| {
                t == v.num.to_string()
                    || t == v.name
                    || Some(t) == v.name.strip_prefix("corerouter-")
            })
            .copied()
            .ok_or_else(|| {
                format!(
                    "unknown lab VM {:?}: {}",
                    t.chars().take(40).collect::<String>(),
                    VMS.iter()
                        .map(|v| format!("{} ({})", v.num, v.name))
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })
    }

    /// `<cputune>` for `cpus` vCPUs.
    fn cputune(&self, cpus: u32) -> String {
        cputune_xml(cpus, self.vcpu_cpus, self.emulator_cpus)
    }
}

/// The host CPUs of `vm` (its vCPUs and QEMU's threads): what a quiet
/// measurement keeps free of the host's processes (G0.26d).
fn measurement_cpus(vm: &Vm) -> std::collections::BTreeSet<u32> {
    let mut set: std::collections::BTreeSet<u32> = vm.vcpu_cpus.iter().copied().collect();
    set.extend(quiet::parse_cpus(vm.emulator_cpus).unwrap_or_default());
    set
}

/// `<cputune>`: vCPU i on `vcpu_cpus[i % len]`, QEMU's threads on `emulator`.
pub(crate) fn cputune_xml(cpus: u32, vcpu_cpus: &[u32], emulator: &str) -> String {
    let mut s = String::from("  <cputune>\n");
    for (vcpu, cpu) in pin_plan(cpus, vcpu_cpus) {
        s.push_str(&format!("    <vcpupin vcpu='{vcpu}' cpuset='{cpu}'/>\n"));
    }
    s.push_str(&format!(
        "    <emulatorpin cpuset='{emulator}'/>\n  </cputune>\n"
    ));
    s
}

/// `(vcpu, host cpu)` for each of `cpus` vCPUs.
fn pin_plan(cpus: u32, vcpu_cpus: &[u32]) -> Vec<(u32, u32)> {
    if vcpu_cpus.is_empty() {
        return Vec::new();
    }
    (0..cpus)
        .filter_map(|v| {
            let i = usize::try_from(v).ok()? % vcpu_cpus.len();
            vcpu_cpus.get(i).map(|c| (v, *c))
        })
        .collect()
}

/// What `run` knows about one VM when it picks (`pick`).
#[derive(Clone, Copy, Debug)]
struct Candidate {
    vm: Vm,
    /// Defined in libvirt (running or not: `run` boots it).
    exists: bool,
    /// Rounds in it now, plus one if a `run` is between its health check and
    /// its round (holds that VM's `health.lock`).
    busy: usize,
}

/// The VM a `run` with no `--vm` uses: `--perf` → VM 1; else a free one,
/// VM 2 first (VM 1 stays free for measurements); none free → the one with
/// the fewest rounds, VM 2 on a tie. Only VMs that exist count; with none,
/// VM 1 (whose error says how to create it).
fn pick(cands: &[Candidate], perf: bool) -> Vm {
    let first = VMS[0];
    if perf {
        return first;
    }
    let mut order: Vec<&Candidate> = cands.iter().filter(|c| c.exists).collect();
    // VM 2 before VM 1, then by number.
    order.sort_by_key(|c| (c.vm.num == 1, c.vm.num));
    order.iter().min_by_key(|c| c.busy).map_or(first, |c| c.vm)
}
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
/// `run`'s health check: below these the VM counts as unhealthy (MiB free
/// in `LAB_ROOT`, MiB of `MemAvailable`).
const MIN_DISK_MIB: u64 = 2048;
const MIN_MEM_MIB: u64 = 1024;
/// What the disk cleanup frees up to: room for a release build of the
/// daemon and the CLI (~4 GiB, **estimated**) above the health limit.
const CLEAN_GOAL_MIB: u64 = 6144;
/// How often a `run` that found the VM unhealthy under a live round looks
/// again.
const RECHECK_EVERY: Duration = Duration::from_secs(30);
/// Held on the host by a `run` from its health check until its round's ssh
/// has started (or the run gives up): one check, cleanup or reset at a time,
/// and none while another run is between its check and its round.
const HEALTH_LOCK: &str = "health.lock";
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

const HELP: &str = "usage: cargo xtask vm-lab [--vm 1|2] <subcommand>
  Two VMs (G0.26c): 1 = corerouter-lab (measurements), 2 = corerouter-lab2
  (functional tests). --vm (or $COREROUTER_VM_LAB) picks one; without it `run`
  takes the free one (VM 2 first), `status`/`unlock` show both, the rest use VM 1.
  create [--cpus N] [--memory MiB] [--disk GiB] [--wires N] [--from 1]
                    download + verify the Ubuntu 24.04 image, make the VM, provision
                    it (packages, rustup) and take the `clean` snapshot; --from 1
                    clones VM 1's `tools` snapshot instead (no install, ~2 min)
                    (defaults: VM 1 8 vCPUs, 16384 MiB, 40 GiB; VM 2 4 vCPUs, 6144 MiB,
                    30 GiB; thin; 1 wire = 2 test NICs)
  up | down         start (and wait for SSH) | shut down
  ssh [cmd...]      shell (or one command) as user `lab`; `sudo` works inside
  sync              rsync this worktree to /srv/lab/<worktree>/src (no target*, .git)
  put <file...>     copy host files into /srv/lab/inbox/ (a .deb, a capture)
  status            state, CPU map, address, who holds the VM lock and for how long
  run [--perf [--no-quiet]] [--vm N] [--no-sync] [--shared] [--lock-timeout 30m] -- <cmd...>
                    --perf: a measurement, on VM 1; else the free VM (VM 2 first). While a
                    --perf round holds the lock, this user's host processes leave VM 1's
                    CPUs (8-15, 24-31) and get them back at the end (--no-quiet, or
                    $COREROUTER_VM_QUIET=0, does not).
                    health check (short disk: drop the build caches no round uses; broken:
                    reset to `tools`/`clean`, but only with no other round in the VM, else
                    wait and check again within --lock-timeout), sync, then run
                    <cmd> as root in /srv/lab/<worktree>/src with
                    CARGO_TARGET_DIR=/srv/lab/<worktree>/target (kept: incremental);
                    one run at a time per VM unless --shared (builds only, no namespaces).
                    Waits for the lock up to --lock-timeout (or $COREROUTER_VM_LOCK_TIMEOUT;
                    default 30m; s/m/h), then fails showing who holds it. Warns about
                    processes the command left running
  pick [--perf]     print the number of the VM a `run` would take now (for scripts that
                    `put` or `ssh` before their `run`: COREROUTER_VM_LAB=$(… pick))
  pin [--vm 1|2|ci] [--force]
                    apply the CPU map of docs/vm-lab.md live (virsh vcpupin/emulatorpin,
                    no restart): both lab VMs and the CI runner; a lab VM in a round is
                    skipped unless --force
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
    match dispatch(root, args) {
        Ok(()) => Outcome::Ok,
        Err(e) => Outcome::Fail(e),
    }
}

/// `--vm <x>` / `--vm=<x>` at the front of `args` (before the subcommand),
/// else `$COREROUTER_VM_LAB`; `None`: not chosen (`run` picks, `status` and
/// `unlock` show every VM, the rest use VM 1).
fn front_vm(args: &[String], env: Option<&str>) -> Result<(Option<Vm>, Vec<String>), String> {
    let mut chosen = None;
    let mut rest = args;
    loop {
        match rest {
            [flag, value, tail @ ..] if flag == "--vm" => {
                chosen = Some(Vm::parse(value)?);
                rest = tail;
            }
            [flag, tail @ ..] if flag.starts_with("--vm=") => {
                chosen = Some(Vm::parse(flag.trim_start_matches("--vm="))?);
                rest = tail;
            }
            [flag] if flag == "--vm" => return Err("--vm needs a value (1, 2)".into()),
            _ => break,
        }
    }
    if chosen.is_none()
        && let Some(e) = env.filter(|e| !e.trim().is_empty())
    {
        chosen = Some(Vm::parse(e).map_err(|err| format!("${VM_VAR}: {err}"))?);
    }
    Ok((chosen, rest.to_vec()))
}

fn dispatch(root: &Path, args: &[String]) -> Result<(), String> {
    let env = std::env::var(VM_VAR).ok();
    let (chosen, args) = front_vm(args, env.as_deref())?;
    let (sub, rest) = match args.split_first() {
        Some((s, r)) => (s.as_str(), r),
        None => ("", &[][..]),
    };
    let dir = vm_dir(root)?;
    // A `run --perf` killed while quieting left the host's CPUs narrowed.
    quiet::recover(&dir);
    let lab = |vm: Vm| Lab {
        root: root.to_path_buf(),
        dir: dir.clone(),
        vm,
    };
    let one = lab(chosen.unwrap_or(VMS[0]));
    match sub {
        "create" => one.create(rest),
        "up" => one.up(),
        "down" => one.down(),
        // No `--vm`: every VM.
        "status" => match chosen {
            Some(_) => one.status(),
            None => each_vm(&lab, "status", |l| l.status()),
        },
        "unlock" => match chosen {
            Some(_) => one.unlock(rest),
            None => each_vm(&lab, "unlock", |l| l.unlock(rest)),
        },
        "pin" => pin(&lab, chosen, rest),
        "pick" => {
            let perf = match rest {
                [] => false,
                [a] if a == "--perf" => true,
                _ => return Err(format!("usage: cargo xtask vm-lab pick [--perf]\n{HELP}")),
            };
            let vm = match chosen {
                Some(v) => v,
                None => lab(VMS[0]).pick(perf)?,
            };
            println!("{}", vm.num);
            Ok(())
        }
        "ssh" => one.ssh_interactive(rest),
        "sync" => one.up().and_then(|()| one.sync()),
        "put" => one.put(rest),
        "run" => {
            let (opts, cmd) = parse_run(rest, std::env::var(LOCK_TIMEOUT_VAR).ok().as_deref())?;
            let vm = match run_vm(chosen, &opts)? {
                Some(v) => v,
                None => lab(VMS[0]).pick(opts.perf)?,
            };
            lab(vm).run(&opts, &cmd)
        }
        "tools" => one.tools(rest),
        "snapshot" | "reset" => {
            let force = rest.iter().any(|a| a == "--force");
            let named = rest.iter().find(|a| !a.starts_with("--")).cloned();
            let name = match named {
                Some(n) => n,
                None if sub == "reset" => one.base_snapshot()?.to_owned(),
                None => TOOLS_SNAPSHOT.to_owned(),
            };
            if !force {
                one.idle()?;
            }
            if sub == "reset" {
                one.reset(&name)
            } else {
                one.snapshot(&name)
            }
        }
        "destroy" => one.destroy(),
        "" | "-h" | "--help" | "help" => {
            eprintln!("{HELP}");
            Ok(())
        }
        other => Err(format!("unknown subcommand '{other}'\n{HELP}")),
    }
}

/// `f` on every VM that exists (VM 1 always, for its "not created" line),
/// each under a `== name (role)` header; the first error is returned after
/// all ran.
fn each_vm(
    lab: &dyn Fn(Vm) -> Lab,
    what: &str,
    f: impl Fn(&Lab) -> Result<(), String>,
) -> Result<(), String> {
    let mut first_err = None;
    for vm in VMS {
        let l = lab(vm);
        if vm.num != 1 && l.state()?.is_none() {
            println!(
                "== {} ({}): not created (`cargo xtask vm-lab --vm {} create --from 1`)",
                vm.name, vm.role, vm.num
            );
            continue;
        }
        println!("== {} ({})", vm.name, vm.role);
        if let Err(e) = f(&l) {
            eprintln!("vm-lab: {what} {}: {e}", vm.name);
            first_err.get_or_insert(e);
        }
    }
    first_err.map_or(Ok(()), Err)
}

/// `vm/` of the main checkout, or `$COREROUTER_VM_DIR`.
fn vm_dir(root: &Path) -> Result<PathBuf, String> {
    if let Some(d) = std::env::var_os("COREROUTER_VM_DIR") {
        return Ok(PathBuf::from(d));
    }
    // Every worktree shares the main checkout's `vm/`.
    let common = output(Command::new("git").current_dir(root).args([
        "rev-parse",
        "--path-format=absolute",
        "--git-common-dir",
    ]))?;
    let common = PathBuf::from(common.trim());
    Ok(common
        .parent()
        .ok_or_else(|| format!("git common dir {} has no parent", common.display()))?
        .join("vm"))
}

/// `vm-lab pin [--force]`: the CPU map of `docs/vm-lab.md` applied live and
/// in the definition (`virsh vcpupin/emulatorpin --live --config`), with no
/// restart. No `--vm`: both lab VMs and the CI runner (`--vm ci`: only it).
/// A lab VM with a round in it is skipped unless `--force` (moving a VM's
/// threads is harmless, but its round would measure across the change).
fn pin(lab: &dyn Fn(Vm) -> Lab, chosen: Option<Vm>, rest: &[String]) -> Result<(), String> {
    let (force, target) = parse_pin(rest)?;
    let (chosen, ci_only) = match target {
        Some(PinTarget::Ci) => (None, true),
        Some(PinTarget::Lab(v)) => (Some(v), false),
        None => (chosen, false),
    };
    let mut plan: Vec<PinJob> = Vec::new();
    if !ci_only {
        for vm in VMS {
            if chosen.is_some_and(|c| c != vm) {
                continue;
            }
            let l = lab(vm);
            let Some(state) = l.state()? else {
                continue;
            };
            let cpus = if state == "running" {
                vcpu_count(&virsh(&["vcpucount", vm.name, "--live"])?)
            } else {
                vcpu_count(&virsh(&["vcpucount", vm.name, "--config"])?)
            }
            .unwrap_or(vm.cpus);
            plan.push(PinJob {
                name: vm.name,
                cpus,
                vcpu_cpus: vm.vcpu_cpus,
                emulator: vm.emulator_cpus,
                lab: Some(l),
            });
        }
    }
    if (chosen.is_none() || ci_only)
        && let Ok(out) = virsh(&["vcpucount", CI_NAME, "--config"])
    {
        plan.push(PinJob {
            name: CI_NAME,
            cpus: vcpu_count(&out).unwrap_or(16),
            vcpu_cpus: CI_VCPU_CPUS,
            emulator: CI_EMULATOR_CPUS,
            lab: None,
        });
    }
    for PinJob {
        name,
        cpus,
        vcpu_cpus,
        emulator,
        lab: l,
    } in plan
    {
        if let Some(l) = &l
            && !force
            && let Err(why) = l.idle()
        {
            println!("{name}: not pinned now ({why}); run `pin` again when it is free");
            continue;
        }
        let running = Command::new("virsh")
            .args(["-c", URI, "domstate", name])
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).trim() == "running");
        let scope: &[&str] = if running {
            &["--live", "--config"]
        } else {
            &["--config"]
        };
        for (vcpu, cpu) in pin_plan(cpus, vcpu_cpus) {
            let (v, c) = (vcpu.to_string(), cpu.to_string());
            let mut a = vec!["vcpupin", name, v.as_str(), c.as_str()];
            a.extend_from_slice(scope);
            virsh(&a)?;
        }
        let mut a = vec!["emulatorpin", name, emulator];
        a.extend_from_slice(scope);
        virsh(&a)?;
        println!(
            "{name}: {cpus} vCPUs on host CPUs {}, emulator on {emulator}{}",
            cpu_list(vcpu_cpus, cpus),
            if running {
                " (live and in the definition)"
            } else {
                " (in the definition)"
            }
        );
    }
    Ok(())
}

/// `virsh vcpupin` and `emulatorpin` tables in one line, and whether they
/// match the map in `VMS`.
fn pin_summary(vcpupin: &str, emulatorpin: &str, want: &[u32], want_emu: &str) -> String {
    let rows: Vec<(u32, String)> = vcpupin
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let v = f.next()?.parse().ok()?;
            Some((v, f.next()?.to_owned()))
        })
        .collect();
    let emu = emulatorpin
        .lines()
        .find_map(|l| l.trim().strip_prefix("*:"))
        .map(str::trim)
        .unwrap_or("?");
    let pairs = rows
        .iter()
        .map(|(v, c)| format!("{v}→{c}"))
        .collect::<Vec<_>>()
        .join(" ");
    let cpus = u32::try_from(rows.len()).unwrap_or(0);
    let expected: Vec<(u32, String)> = pin_plan(cpus, want)
        .into_iter()
        .map(|(v, c)| (v, c.to_string()))
        .collect();
    let verdict = if rows == expected && emu == want_emu {
        "as in docs/vm-lab.md"
    } else {
        "not the map of docs/vm-lab.md: `cargo xtask vm-lab pin`"
    };
    format!("vCPU→CPU {pairs}; emulator {emu} ({verdict})")
}

/// One VM for `pin`: its map, and the lab (for the round check) unless it
/// is the CI runner.
struct PinJob {
    name: &'static str,
    cpus: u32,
    vcpu_cpus: &'static [u32],
    emulator: &'static str,
    lab: Option<Lab>,
}

/// What `pin --vm <x>` names: a lab VM or the CI runner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PinTarget {
    Lab(Vm),
    Ci,
}

/// `pin [--vm 1|2|ci] [--force]`: `(force, target)`.
fn parse_pin(rest: &[String]) -> Result<(bool, Option<PinTarget>), String> {
    let mut force = false;
    let mut target = None;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        let named = match a.as_str() {
            "--force" => {
                force = true;
                continue;
            }
            "--vm" => it
                .next()
                .ok_or_else(|| "--vm needs a value (1, 2, ci)".to_owned())?,
            f if f.starts_with("--vm=") => f.trim_start_matches("--vm="),
            other => return Err(format!("pin: unknown option {other}\n{HELP}")),
        };
        target = Some(if named == "ci" || named == CI_NAME {
            PinTarget::Ci
        } else {
            PinTarget::Lab(Vm::parse(named)?)
        });
    }
    Ok((force, target))
}

/// The number in `virsh vcpucount <dom> --live|--config` (one line).
fn vcpu_count(out: &str) -> Option<u32> {
    out.split_whitespace().last()?.parse().ok()
}

/// `8-15` style list of the CPUs the first `cpus` vCPUs use.
fn cpu_list(vcpu_cpus: &[u32], cpus: u32) -> String {
    let mut used: Vec<u32> = pin_plan(cpus, vcpu_cpus)
        .into_iter()
        .map(|(_, c)| c)
        .collect();
    used.sort_unstable();
    used.dedup();
    let mut parts: Vec<String> = Vec::new();
    let mut i = 0;
    while let Some(&lo) = used.get(i) {
        let mut hi = lo;
        while used.get(i + 1) == Some(&(hi + 1)) {
            hi += 1;
            i += 1;
        }
        parts.push(if hi == lo {
            lo.to_string()
        } else {
            format!("{lo}-{hi}")
        });
        i += 1;
    }
    parts.join(",")
}

/// The VM a `run` names (front `--vm`/`$COREROUTER_VM_LAB` first, then its
/// own `--vm`); `None`: pick the free one. `--perf` is VM 1 only.
fn run_vm(front: Option<Vm>, opts: &RunOpts) -> Result<Option<Vm>, String> {
    match (front.or(opts.vm), opts.perf) {
        (Some(v), true) if v.num != 1 => Err(format!(
            "--perf runs on VM 1 ({}), not {}: drop --vm, or --perf",
            VMS[0].name, v.name
        )),
        (Some(v), _) => Ok(Some(v)),
        (None, true) => Ok(Some(VMS[0])),
        (None, false) => Ok(None),
    }
}

/// The options of `vm-lab run` (before `--`).
#[derive(Debug, PartialEq, Eq)]
struct RunOpts {
    sync: bool,
    exclusive: bool,
    timeout_s: u64,
    /// `--vm` among the run options (the front `--vm` wins).
    vm: Option<Vm>,
    /// `--perf`: a measurement, VM 1.
    perf: bool,
    /// `--perf` quiets VM 1's host CPUs during the round (G0.26d);
    /// `--no-quiet` or `$COREROUTER_VM_QUIET=0` does not.
    quiet: bool,
}

/// `run`'s options, then the command. `env_timeout`: `$COREROUTER_VM_LOCK_TIMEOUT`.
fn parse_run(args: &[String], env_timeout: Option<&str>) -> Result<(RunOpts, Vec<String>), String> {
    let mut o = RunOpts {
        sync: true,
        exclusive: true,
        timeout_s: match env_timeout {
            Some(v) => parse_duration(v).map_err(|e| format!("${LOCK_TIMEOUT_VAR}: {e}"))?,
            None => LOCK_TIMEOUT_DEFAULT,
        },
        vm: None,
        perf: false,
        quiet: true,
    };
    let mut rest = args;
    while let Some((first, tail)) = rest.split_first() {
        let value = |name: &str| -> Result<(&String, &[String]), String> {
            tail.split_first()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match first.as_str() {
            "--no-sync" => o.sync = false,
            "--shared" => o.exclusive = false,
            "--perf" => o.perf = true,
            "--no-quiet" => o.quiet = false,
            "--lock-timeout" => {
                let (v, t) = value("--lock-timeout (30m, 900, 1h)")?;
                o.timeout_s = parse_duration(v).map_err(|e| format!("--lock-timeout: {e}"))?;
                rest = t;
                continue;
            }
            "--vm" => {
                let (v, t) = value("--vm (1, 2)")?;
                o.vm = Some(Vm::parse(v)?);
                rest = t;
                continue;
            }
            f if f.starts_with("--lock-timeout=") => {
                let v = f.trim_start_matches("--lock-timeout=");
                o.timeout_s = parse_duration(v).map_err(|e| format!("--lock-timeout: {e}"))?;
            }
            f if f.starts_with("--vm=") => o.vm = Some(Vm::parse(f.trim_start_matches("--vm="))?),
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
    Ok((o, rest.to_vec()))
}

struct Lab {
    /// The worktree being worked on (what `sync` copies).
    root: PathBuf,
    /// `vm/` of the main checkout, or `$COREROUTER_VM_DIR`: shared by every VM
    /// (the cloud image in `base/`, the `.deb`s in `tools/`).
    dir: PathBuf,
    vm: Vm,
}

struct Spec {
    cpus: u32,
    memory_mib: u32,
    disk_gib: u32,
    wires: u32,
}

impl Lab {
    /// This VM's own file (`vm/<file>` for VM 1, `vm/<subdir>/<file>` else).
    fn path(&self, name: &str) -> PathBuf {
        self.vm_dir().join(name)
    }

    fn vm_dir(&self) -> PathBuf {
        match self.vm.subdir {
            Some(sub) => self.dir.join(sub),
            None => self.dir.clone(),
        }
    }

    /// A file every VM shares (`vm/base`, `vm/tools`).
    fn shared(&self, name: &str) -> PathBuf {
        self.dir.join(name)
    }

    /// The VM for a `run` that did not name one (`pick`). Busy: the rounds in
    /// each VM, seen from this host, plus a `run` between its health check
    /// and its round (holding that VM's `health.lock`).
    fn pick(&self, perf: bool) -> Result<Vm, String> {
        let own = own_round();
        let mut cands = Vec::new();
        for vm in VMS {
            let l = Lab {
                root: self.root.clone(),
                dir: self.dir.clone(),
                vm,
            };
            let exists = l.state()?.is_some();
            let mut busy = live_rounds(&own, &l.path(HOST_LOCK), vm.name).len();
            if l.health_lock_busy() {
                busy += 1;
            }
            cands.push(Candidate { vm, exists, busy });
        }
        let vm = pick(&cands, perf);
        let line = cands
            .iter()
            .filter(|c| c.exists)
            .map(|c| format!("{} {} round(s)", c.vm.name, c.busy))
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!(
            "vm-lab: {} ({}){}; `--vm N` chooses",
            vm.name,
            if perf { "--perf" } else { "the free one" },
            if line.is_empty() {
                String::new()
            } else {
                format!(" [{line}]")
            }
        );
        Ok(vm)
    }

    /// Another `run` holds this VM's `health.lock` right now.
    fn health_lock_busy(&self) -> bool {
        let Ok(file) = std::fs::File::open(self.path(HEALTH_LOCK)) else {
            return false;
        };
        match file.try_lock_shared() {
            Ok(()) => {
                let _ = file.unlock();
                false
            }
            Err(_) => true,
        }
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
        let vm = self.vm.name;
        let (spec, from) = parse_spec(args, &self.vm)?;
        if self.state()?.is_some() {
            return Err(format!(
                "{vm} already exists: `cargo xtask vm-lab destroy` first (or `reset`)"
            ));
        }
        let started = Instant::now();
        std::fs::create_dir_all(self.vm_dir())
            .map_err(|e| format!("{}: {e}", self.vm_dir().display()))?;
        std::fs::create_dir_all(self.shared("base"))
            .map_err(|e| format!("{}: {e}", self.dir.display()))?;
        let base = cloud_image(&self.shared("base"))?;
        self.keys()?;
        self.seed(&spec)?;
        let overlay = self.path(&format!("{vm}.qcow2"));
        let _ = std::fs::remove_file(&overlay);
        let cloned = match from {
            Some(src) => Some(self.clone_disk(src, &base, &overlay, spec.disk_gib)?),
            None => {
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
                None
            }
        };
        let xml = self.path(&format!("{vm}.xml"));
        std::fs::write(&xml, self.domain_xml(&spec, &overlay))
            .map_err(|e| format!("{}: {e}", xml.display()))?;
        virsh(&["define", &xml.to_string_lossy()])?;
        virsh(&["start", vm])?;
        eprintln!("vm-lab: {vm} defined and started; waiting for cloud-init (packages)…");
        self.wait_ssh(Duration::from_secs(600))?;
        // `status --wait` exits 2 for "done with recoverable errors" (a
        // deprecation warning is enough): the long form says what it was.
        let status =
            self.ssh_output("cloud-init status --wait >/dev/null; cloud-init status --long; true")?;
        eprintln!("{}", status.trim());
        if !status.contains("status: done") {
            return Err(format!("cloud-init did not finish:\n{status}"));
        }
        if cloned.is_some() {
            self.own_clone()?;
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
        virsh(&["change-media", vm, "sda", "--eject", "--config"])?;
        // A clone keeps the name of the snapshot it came from (`tools`).
        self.snapshot(cloned.unwrap_or("clean"))?;
        eprintln!(
            "vm-lab: {vm} ready in {:.0} s ({} vCPUs, {} MiB, {} wire(s)); `cargo xtask vm-lab status`",
            started.elapsed().as_secs_f64(),
            spec.cpus,
            spec.memory_mib,
            spec.wires
        );
        Ok(())
    }

    /// VM 2 from VM 1 (G0.26c): the disk of `src`'s base snapshot (`tools`,
    /// with the third-party tools the user installed there, or `clean`), as
    /// an overlay on the same cloud image. Read with `-U` while `src` runs: a
    /// snapshot's clusters never change while it exists (a write to them is
    /// copied first), so nothing of `src` is stopped or touched. The new seed
    /// (own `instance-id`, hostname, MACs, host key) makes cloud-init treat
    /// the copy as a new machine. Returns the snapshot's name.
    fn clone_disk(
        &self,
        src: Vm,
        base: &Path,
        overlay: &Path,
        disk_gib: u32,
    ) -> Result<&'static str, String> {
        let from = Lab {
            root: self.root.clone(),
            dir: self.dir.clone(),
            vm: src,
        };
        from.require()?;
        let snap = from.base_snapshot()?;
        let src_disk = from.path(&format!("{}.qcow2", src.name));
        let started = Instant::now();
        eprintln!(
            "vm-lab: cloning snapshot `{snap}` of {} into {}…",
            src.name,
            overlay.display()
        );
        run_ok(
            Command::new("qemu-img")
                .args(["convert", "-U", "-O", "qcow2", "-B"])
                .arg(base)
                .args(["-F", "qcow2", "-l"])
                .arg(format!("snapshot.name={snap}"))
                .arg(&src_disk)
                .arg(overlay),
        )?;
        let info = output(Command::new("qemu-img").args([
            "info",
            "--output=json",
            &overlay.to_string_lossy(),
        ]))?;
        let have = json_u64(&info, "virtual-size").unwrap_or(0);
        let want = u64::from(disk_gib) << 30;
        if want > have {
            run_ok(Command::new("qemu-img").args([
                "resize",
                "-q",
                &overlay.to_string_lossy(),
                &format!("{disk_gib}G"),
            ]))?;
        } else if want < have {
            eprintln!(
                "vm-lab: --disk {disk_gib} is under the source's {} GiB; kept {} GiB",
                have >> 30,
                have >> 30
            );
        }
        let size = std::fs::metadata(overlay)
            .map(|m| m.len() >> 20)
            .unwrap_or(0);
        eprintln!(
            "vm-lab: cloned in {:.0} s ({size} MiB on the host)",
            started.elapsed().as_secs_f64()
        );
        Ok(snap)
    }

    /// After the first boot of a clone: only this VM's key logs in (the
    /// users module of cloud-init adds keys, it never removes the source's),
    /// and its own machine id (journal, DHCP's DUID).
    fn own_clone(&self) -> Result<(), String> {
        let key = read(&self.path("id_ed25519.pub"))?;
        let script = format!(
            "set -e\n\
             printf '%s\\n' {key} > /home/{USER}/.ssh/authorized_keys\n\
             chown {USER}:{USER} /home/{USER}/.ssh/authorized_keys\n\
             chmod 600 /home/{USER}/.ssh/authorized_keys\n\
             rm -f /etc/machine-id\n\
             systemd-machine-id-setup >/dev/null\n\
             hostname\n",
            key = shell_quote(key.trim()),
        );
        self.ssh_root_script(&script)
    }

    /// The lab's own client key and the VM's host key (pinned in
    /// `known_hosts` under the alias `corerouter-lab`, so a new address
    /// from DHCP never asks to trust anything).
    fn keys(&self) -> Result<(), String> {
        let vm = self.vm.name;
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
                    &format!("{vm}-{key}"),
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
        write(&self.path("known_hosts"), &format!("{vm} {kind} {key}\n"))
    }

    fn seed(&self, spec: &Spec) -> Result<(), String> {
        let vm = self.vm.name;
        let seed = self.path("seed");
        std::fs::create_dir_all(&seed).map_err(|e| format!("{}: {e}", seed.display()))?;
        let client = read(&self.path("id_ed25519.pub"))?;
        let host_key = read(&self.path("ssh_host_ed25519_key"))?;
        let host_pub = read(&self.path("ssh_host_ed25519_key.pub"))?;
        let indented: String = host_key.lines().map(|l| format!("    {l}\n")).collect();
        let packages: String = PACKAGES.iter().map(|p| format!("  - {p}\n")).collect();
        let user_data = format!(
            "#cloud-config\n\
             hostname: {vm}\n\
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
        let instance = format!("{vm}-{}", unix_now());
        let meta = format!("instance-id: {instance}\nlocal-hostname: {vm}\n");
        let mut net = format!(
            "version: 2\nethernets:\n  mgmt0:\n    match:\n      macaddress: \"{mgmt_mac}\"\n    \
             set-name: mgmt0\n    dhcp4: true\n    dhcp6: false\n    dhcp-identifier: mac\n",
            mgmt_mac = self.vm.mgmt_mac
        );
        for (name, mac) in wire_nics(spec.wires, self.vm.wire_mac_prefix) {
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
        let vm = self.vm.name;
        let mut nics = format!(
            "    <interface type='network'>\n      <source network='default'/>\n      \
             <mac address='{mgmt_mac}'/>\n      <model type='virtio'/>\n    </interface>\n",
            mgmt_mac = self.vm.mgmt_mac
        );
        let base = self.vm.wire_port_base;
        for (i, (_, mac)) in wire_nics(spec.wires, self.vm.wire_mac_prefix)
            .into_iter()
            .enumerate()
        {
            // NIC 2k sends to the port NIC 2k+1 listens on, and back.
            let pair = u16::try_from(i / 2).unwrap_or(0);
            let (local, remote) = if i % 2 == 0 {
                (base + 2 * pair, base + 2 * pair + 1)
            } else {
                (base + 2 * pair + 1, base + 2 * pair)
            };
            nics.push_str(&format!(
                "    <interface type='udp'>\n      <mac address='{mac}'/>\n      \
                 <source address='127.0.0.1' port='{remote}'>\n        \
                 <local address='127.0.0.1' port='{local}'/>\n      </source>\n      \
                 <model type='virtio'/>\n    </interface>\n"
            ));
        }
        // `cputune`: the CPU map of `VMS` (G0.26c). `freePageReporting`: the
        // guest hands the pages it frees back to the host (the host swapped
        // 19.5 GB when VM 2 was made, **measured**).
        // `host-model`, not `host-passthrough`: passthrough hands the guest
        // the host's CET shadow stack (KVM on kernel 7.0 offers it), which
        // QEMU 8.2 does not manage; after a while every process in the VM
        // segfaulted at the same shadow-stack address (**measured**,
        // 2026-10-25).
        format!(
            "<domain type='kvm'>\n  <name>{vm}</name>\n  \
             <description>CoreRouter VM lab (cargo xtask vm-lab, docs/vm-lab.md)</description>\n  \
             <memory unit='MiB'>{mem}</memory>\n  <vcpu>{cpus}</vcpu>\n{cputune}  \
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
             <rng model='virtio'><backend model='random'>/dev/urandom</backend></rng>\n    \
             <memballoon model='virtio' freePageReporting='on'/>\n  \
             </devices>\n</domain>\n",
            mem = spec.memory_mib,
            cpus = spec.cpus,
            cputune = self.vm.cputune(spec.cpus),
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
        let vm = self.vm.name;
        let out = Command::new("virsh")
            .args(["-c", URI, "domstate", vm])
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
        let vm = self.vm.name;
        self.state()?
            .ok_or_else(|| format!("{vm} does not exist: `cargo xtask vm-lab create`"))
    }

    fn up(&self) -> Result<(), String> {
        let vm = self.vm.name;
        if self.require()? != "running" {
            virsh(&["start", vm])?;
        }
        self.wait_ssh(Duration::from_secs(180))?;
        // A `reset` to an older snapshot may predate a guest setting.
        if self.guest_settings()? {
            eprintln!("vm-lab: guest boot settings applied; rebooting");
            self.down()?;
            virsh(&["start", vm])?;
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
        let vm = self.vm.name;
        if self.require()? != "running" {
            return Ok(());
        }
        self.close_master();
        virsh(&["shutdown", vm])?;
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
        virsh(&["destroy", vm]).map(|_| ())
    }

    fn destroy(&self) -> Result<(), String> {
        let vm = self.vm.name;
        if let Some(state) = self.state()? {
            self.close_master();
            if state == "running" {
                let _ = virsh(&["destroy", vm]);
            }
            virsh(&["undefine", vm, "--snapshots-metadata"])?;
        }
        for f in [
            format!("{vm}.qcow2"),
            "seed.iso".into(),
            format!("{vm}.xml"),
        ] {
            let _ = std::fs::remove_file(self.path(&f));
        }
        eprintln!("vm-lab: {vm} destroyed (vm/base/ cache and the lab key stay)");
        Ok(())
    }

    fn snapshot(&self, name: &str) -> Result<(), String> {
        let vm = self.vm.name;
        check_snapshot_name(name)?;
        let was_running = self.require()? == "running";
        // Offline: an internal disk snapshot, no RAM image (8 GB) to store.
        self.down()?;
        if virsh(&["snapshot-list", vm, "--name"])?
            .lines()
            .any(|l| l.trim() == name)
        {
            virsh(&["snapshot-delete", vm, name])?;
        }
        virsh(&["snapshot-create-as", vm, name, "--atomic"])?;
        eprintln!("vm-lab: snapshot `{name}` taken");
        if was_running { self.up() } else { Ok(()) }
    }

    fn reset(&self, name: &str) -> Result<(), String> {
        let vm = self.vm.name;
        check_snapshot_name(name)?;
        let started = Instant::now();
        if self.require()? == "running" {
            self.close_master();
            virsh(&["destroy", vm])?;
        }
        // A revert also brings back the definition saved with the snapshot
        // (CPU, memory): keep the current one.
        let current = virsh(&["dumpxml", "--inactive", "--security-info", vm])?;
        virsh(&["snapshot-revert", vm, name])?;
        let xml = self.path(&format!("{vm}.xml"));
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
        let vm = self.vm.name;
        let list = virsh(&["snapshot-list", vm, "--name"])?;
        Ok(if list.lines().any(|l| l.trim() == TOOLS_SNAPSHOT) {
            TOOLS_SNAPSHOT
        } else {
            "clean"
        })
    }

    /// Nobody in a round: neither the user's host lock nor `run`'s lock in
    /// the VM is held. A snapshot or reset would cut that round off.
    fn idle(&self) -> Result<(), String> {
        let vm = self.vm.name;
        let host = self.path(HOST_LOCK);
        if host_lock_held(&host) {
            return Err(format!(
                "{} is held (a round the user runs by hand); try again when it ends, or --force",
                host.display()
            ));
        }
        let live = live_rounds(&own_round(), &host, vm);
        if !live.is_empty() {
            return Err(format!(
                "a `vm-lab run` is in the VM; try again when it ends, or --force\n{}",
                live_list(&live)
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
    /// apart, so one busy moment does not count. `patient` (a round is
    /// alive, the VM may be loaded): longer SSH timeouts, so a slow answer
    /// is not taken for a dead VM.
    fn check(&self, patient: bool) -> Health {
        if let Err(e) = self.up() {
            return Health::Unreachable(e);
        }
        let (connect_s, limit) = if patient {
            (30, Duration::from_secs(180))
        } else {
            (10, Duration::from_secs(60))
        };
        let mut last = Health::Ok;
        for attempt in 0..2 {
            if attempt > 0 {
                std::thread::sleep(Duration::from_secs(3));
            }
            last = self.probe(connect_s, limit);
            if last == Health::Ok {
                break;
            }
        }
        last
    }

    fn probe(&self, connect_s: u32, limit: Duration) -> Health {
        let ip = match self.address() {
            Ok(Some(ip)) => ip,
            Ok(None) => return Health::Unreachable("no address yet".into()),
            Err(e) => return Health::Unreachable(e),
        };
        let mut c = self.ssh_base_with(&ip, connect_s);
        c.arg(format!("sudo -n bash -c {}", shell_quote(&health_script())));
        match output_within(&mut c, limit) {
            Err(e) => Health::Unreachable(e),
            Ok(None) => Health::Unreachable(format!("no answer by SSH in {} s", limit.as_secs())),
            Ok(Some(out)) => classify(
                out.status.code(),
                &String::from_utf8_lossy(&out.stdout),
                &String::from_utf8_lossy(&out.stderr),
            ),
        }
    }

    /// Removes the build caches (`/srv/lab/<worktree>/target`) of the
    /// worktrees no live round uses, least recently built first, until
    /// `CLEAN_GOAL_MIB` are free. `keep`: worktree names left alone (the
    /// live rounds' and this run's own). Sources stay: the next `run` of
    /// that worktree syncs and rebuilds.
    fn clean_disk(&self, keep: &[String]) -> Result<String, String> {
        let mut cmd = format!(
            "sudo -n bash -c {} clean {CLEAN_GOAL_MIB}",
            shell_quote(&format!("root={LAB_ROOT}\n{CLEAN_SH}"))
        );
        for k in keep {
            cmd.push(' ');
            cmd.push_str(&shell_quote(k));
        }
        self.ssh_output(&cmd)
    }

    /// `vm/health.lock`, taken (blocking) for the health check of a `run`.
    fn health_lock(&self) -> Result<std::fs::File, String> {
        let path = self.path(HEALTH_LOCK);
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => {
                eprintln!("vm-lab: another `vm-lab run` is checking the VM; waiting for it");
            }
            Err(std::fs::TryLockError::Error(e)) => {
                return Err(format!("{}: {e}", path.display()));
            }
        }
        file.lock()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(file)
    }

    /// The health check of `run`, with what follows from it (`verdict`):
    /// clean the disk, reset a VM nobody is using, or wait while a round is
    /// alive. `Ok` holds `vm/health.lock` (drop it once the round's ssh has
    /// started) and says how long it waited.
    fn ready(&self, timeout: Duration) -> Result<(std::fs::File, Duration), String> {
        let vm = self.vm.name;
        let started = Instant::now();
        let own = own_round();
        let own_dir = self.remote_dir()?;
        let mut cleaned = false;
        let mut reset_done = false;
        let mut said_wait = false;
        let mut last_live: Vec<String> = Vec::new();
        loop {
            let guard = self.health_lock()?;
            let live = live_rounds(&own, &self.path(HOST_LOCK), vm);
            let who: Vec<String> = live.iter().map(|r| r.who.clone()).collect();
            if who != last_live {
                // A round ended (or came): its cache may be removable now.
                cleaned = false;
                last_live = who;
            }
            let health = self.check(!live.is_empty());
            let situation = Situation {
                health: &health,
                live: !live.is_empty(),
                cleaned,
                reset_done,
                out_of_time: started.elapsed() >= timeout,
            };
            match verdict(&situation) {
                Verdict::Go => return Ok((guard, started.elapsed())),
                Verdict::CleanDisk => {
                    cleaned = true;
                    let mut keep: Vec<String> = live.iter().filter_map(|r| r.name()).collect();
                    keep.extend(dir_name(&own_dir));
                    eprintln!(
                        "vm-lab: {vm}: {health}; removing the build caches of worktrees no round uses"
                    );
                    match self.clean_disk(&keep) {
                        Ok(report) => eprint!("{report}"),
                        Err(e) => eprintln!("vm-lab: disk cleanup failed: {e}"),
                    }
                }
                Verdict::Reset => {
                    reset_done = true;
                    let base = self.base_snapshot()?;
                    eprintln!(
                        "vm-lab: {vm} is unhealthy ({health}) and no round is alive; `reset` to `{base}`"
                    );
                    self.reset(base)?;
                }
                Verdict::Wait => {
                    if !said_wait {
                        said_wait = true;
                        eprintln!(
                            "vm-lab: {vm} looks unhealthy ({health}), but a round is alive in it:\n{}\n\
                             vm-lab: no reset (it would cut that round off); checking again every {} s \
                             for up to {} (--lock-timeout)",
                            live_list(&live),
                            RECHECK_EVERY.as_secs(),
                            human_secs(timeout.as_secs())
                        );
                    }
                    drop(guard);
                    let left = timeout.saturating_sub(started.elapsed());
                    std::thread::sleep(RECHECK_EVERY.min(left).max(Duration::from_secs(1)));
                }
                Verdict::GiveUp if reset_done && live.is_empty() => {
                    return Err(format!("{vm} still unhealthy after reset: {health}"));
                }
                Verdict::GiveUp => {
                    return Err(format!(
                        "{vm} is unhealthy ({health}) and still in use after {}:\n{}\n\
                         Not reset: that would cut those rounds off. Run again when they end (the \
                         reset is automatic then), raise --lock-timeout, or, only if those rounds \
                         are stuck, `cargo xtask vm-lab reset --force`",
                        human_secs(started.elapsed().as_secs()),
                        live_list(&live)
                    ));
                }
            }
        }
    }

    fn status(&self) -> Result<(), String> {
        let vm = self.vm.name;
        let Some(state) = self.state()? else {
            println!(
                "{vm}: not created (`cargo xtask vm-lab create`); cache in {}",
                self.dir.display()
            );
            return Ok(());
        };
        println!("{vm}: {state}");
        if self.vm.num == 1
            && let Ok(text) = std::fs::read_to_string(self.shared(quiet::STATE))
            && let Some(q) = quiet::State::parse(&text)
        {
            println!(
                "quiet: round {} keeps {} host process(es) off CPUs {} (G0.26d)",
                q.owner,
                q.moved.len(),
                quiet::format_cpus(&q.avoid)
            );
        }
        let live = if state == "running" {
            "--live"
        } else {
            "--config"
        };
        if let (Ok(v), Ok(e)) = (
            virsh(&["vcpupin", vm, live]),
            virsh(&["emulatorpin", vm, live]),
        ) {
            println!(
                "cpus: {}",
                pin_summary(&v, &e, self.vm.vcpu_cpus, self.vm.emulator_cpus)
            );
        }
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
        let snaps = virsh(&["snapshot-list", vm, "--name"])?;
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
        let overlay = self.path(&format!("{vm}.qcow2"));
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
        let vm = self.vm.name;
        // The guest agent knows the address in use; the lease table may
        // also hold an older lease of the same NIC (a continuation row).
        if let Ok(out) = virsh(&["domifaddr", vm, "--source", "agent"])
            && let Some(ip) = mgmt_ipv4(&out, self.vm.mgmt_mac)
        {
            return Ok(Some(ip));
        }
        Ok(mgmt_ipv4(
            &virsh(&["domifaddr", vm, "--source", "lease"])?,
            self.vm.mgmt_mac,
        ))
    }

    fn ssh_base(&self, ip: &str) -> Command {
        self.ssh_base_with(ip, 5)
    }

    /// `connect_s`: ssh's `ConnectTimeout` (the first value given wins in
    /// ssh, so it cannot be appended later).
    fn ssh_base_with(&self, ip: &str, connect_s: u32) -> Command {
        let vm = self.vm.name;
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
                &format!("HostKeyAlias={vm}"),
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "BatchMode=yes",
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
            .arg(format!("ConnectTimeout={connect_s}"))
            .arg("-o")
            .arg(format!("ControlPath={}/cm-%C", self.vm_dir().display()))
            .arg(format!("{USER}@{ip}"));
        c
    }

    fn ssh(&self) -> Result<Command, String> {
        let vm = self.vm.name;
        let ip = self
            .address()?
            .ok_or_else(|| format!("{vm} has no address yet: `cargo xtask vm-lab up`"))?;
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
        let vm = self.vm.name;
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
                    "{vm} not reachable by SSH after {} s (`virsh -c {URI} console {vm}`)",
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
        let vm = self.vm.name;
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
            Err(format!("command in {vm} failed: {status}"))
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
        exit_like(status, self.vm.name)
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
        let vm = self.vm.name;
        let started = Instant::now();
        let dest = format!("{}/src/", self.remote_dir()?);
        let (mut rsync, to) = self.rsync(&dest)?;
        run_ok(
            rsync
                .args(["-a", "--delete", "--info=stats0"])
                .args(SYNC_EXCLUDES)
                .arg(format!("{}/", self.root.display()))
                .arg(to),
        )?;
        eprintln!(
            "vm-lab: synced {} → {vm}:{dest} in {:.1} s",
            self.root.display(),
            started.elapsed().as_secs_f64()
        );
        Ok(())
    }

    /// The third-party tools of `vm_tools::TOOLS`: `--check` reports, the
    /// default installs what is missing and snapshots `tools`.
    fn tools(&self, args: &[String]) -> Result<(), String> {
        let vm = self.vm.name;
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
            let flag = if self.vm.num == 1 {
                String::new()
            } else {
                format!("--vm {} ", self.vm.num)
            };
            return Err(format!(
                "missing in {vm}: {}. Installing third-party code is the user's call, once: \
                 ask them to run `cargo xtask vm-lab {flag}tools`",
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
        let cache = self.shared("tools");
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
        let vm = self.vm.name;
        if files.is_empty() {
            return Err(format!("nothing to copy\n{HELP}"));
        }
        self.up()?;
        let dest = format!("{LAB_ROOT}/inbox/");
        let (mut rsync, to) = self.rsync(&dest)?;
        run_ok(rsync.arg("-t").args(files).arg(to))?;
        eprintln!("vm-lab: copied {} file(s) to {vm}:{dest}", files.len());
        Ok(())
    }

    fn run(&self, opts: &RunOpts, rest: &[String]) -> Result<(), String> {
        let vm = self.vm.name;
        let (sync, exclusive, timeout) = (opts.sync, opts.exclusive, opts.timeout_s);
        let quiet_off = std::env::var(QUIET_VAR).is_ok_and(|v| v.trim() == "0");
        // Only a measurement that holds VM 1 (not a `--shared` build).
        let quieting = opts.perf && opts.quiet && !quiet_off && exclusive && self.vm.num == 1;
        let started = Instant::now();
        // Unreachable counts as unhealthy too (sshd was among the victims),
        // but nothing is reset under a live round (2026-11-13): see `verdict`.
        let (health_lock, waited) = self.ready(Duration::from_secs(timeout))?;
        let timeout = timeout.saturating_sub(waited.as_secs()).max(1);
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
                marker: quieting,
            }),
        );
        // `bash -c` (not a heredoc on stdin), so the command keeps a
        // terminal-less stdin of its own and `-t` is not needed. `env` puts
        // the round mark in the environment every process of it inherits.
        let mut ssh = self.ssh()?;
        ssh.args(["sudo", "env", &format!("{ROUND_VAR}={round}"), "bash", "-c"])
            .arg(shell_quote(&script))
            .stdin(Stdio::null());
        if quieting {
            ssh.stderr(Stdio::piped());
        }
        let mut child = ssh.spawn().map_err(|e| format!("ssh: {e}"))?;
        // From here the round is visible to the others (`live_rounds`).
        drop(health_lock);
        let quiet = match child.stderr.take() {
            Some(err) => self.quiet_when_locked(err, &round),
            None => None,
        };
        let status = child.wait().map_err(|e| format!("ssh: {e}"))?;
        if let Some((q, relay)) = quiet {
            if let Some(q) = q {
                q.finish();
            }
            let _ = relay.join();
        }
        eprintln!(
            "vm-lab: round (sync + command) in {vm} {:.1} s, {status}",
            started.elapsed().as_secs_f64()
        );
        exit_like(status, vm)
    }

    /// Relays the round's stderr (thread `vm-lab-relay`) and, once the round
    /// script says it holds the lock, starts quieting VM 1's host CPUs.
    /// Returns the quieting (none if it could not start) and the relay to
    /// join after the round.
    #[allow(clippy::type_complexity)]
    fn quiet_when_locked(
        &self,
        mut err: std::process::ChildStderr,
        round: &str,
    ) -> Option<(Option<quiet::Quiet>, std::thread::JoinHandle<()>)> {
        let (tx, rx) = std::sync::mpsc::channel();
        let relay = std::thread::Builder::new()
            .name("vm-lab-relay".into())
            .spawn(move || {
                let mut out = std::io::stderr();
                let found = quiet::relay_until_marker(&mut err, &mut out);
                let _ = tx.send(found);
                let _ = std::io::copy(&mut err, &mut out);
            })
            .map_err(|e| eprintln!("vm-lab: relay thread: {e}"))
            .ok()?;
        // `false`: the round ended (or failed) before taking the lock.
        if !rx.recv().unwrap_or(false) {
            return Some((None, relay));
        }
        let avoid = measurement_cpus(&self.vm);
        let started = quiet::user_scope()
            .and_then(|scope| quiet::Quiet::start(&self.shared(quiet::STATE), round, avoid, scope));
        // Go, quiet or not: the round waits for this file (at most
        // `GO_WAIT_S`) before its command.
        let go = format!("sudo -n touch {}", shell_quote(&quiet::go_file(round)));
        if let Err(e) = self.ssh_output(&go) {
            eprintln!(
                "vm-lab: quiet: could not tell the round to go ({e}); it starts after {} s",
                quiet::GO_WAIT_S
            );
        }
        match started {
            Ok(q) => Some((Some(q), relay)),
            Err(e) => {
                eprintln!("vm-lab: quiet: not started ({e}); measuring without it");
                Some((None, relay))
            }
        }
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
        let vm = self.vm.name;
        let mut force = false;
        for a in args {
            match a.as_str() {
                "--force" => force = true,
                other => return Err(format!("unlock: unknown option {other}\n{HELP}")),
            }
        }
        if self.require()? != "running" {
            println!("{vm} is not running: no round, no lock (it lives in /run)");
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

/// What the health check of `run` found.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Health {
    Ok,
    /// MiB free in `LAB_ROOT`, under `MIN_DISK_MIB`.
    LowDisk(u64),
    /// MiB of `MemAvailable`, under `MIN_MEM_MIB`.
    LowMemory(u64),
    /// Root or a new process fails (the 2026-10-25 shadow-stack breakage).
    Broken(String),
    /// No SSH answer in time (VM down, sshd dead, or very slow).
    Unreachable(String),
}

impl std::fmt::Display for Health {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Health::Ok => write!(f, "healthy"),
            Health::LowDisk(m) => {
                write!(f, "disk: {m} MiB free in {LAB_ROOT}, under {MIN_DISK_MIB}")
            }
            Health::LowMemory(m) => write!(f, "memory: {m} MiB available, under {MIN_MEM_MIB}"),
            Health::Broken(why) => write!(f, "{why}"),
            Health::Unreachable(why) => write!(f, "unreachable: {why}"),
        }
    }
}

/// Root runs, five processes start, then one line `disk=<MiB> mem=<MiB>`.
fn health_script() -> String {
    format!(
        "for i in 1 2 3 4 5; do /bin/true || exit 11; done; \
         echo \"disk=$(df --output=avail -m {LAB_ROOT} | tail -1 | tr -d ' ') \
         mem=$(awk '/MemAvailable/{{print int($2 / 1024)}}' /proc/meminfo)\""
    )
}

/// The answer of `health_script` over ssh: exit code (`None`: killed by a
/// signal), stdout, stderr. 255 is ssh's own failure.
fn classify(code: Option<i32>, out: &str, err: &str) -> Health {
    let err: String = err.trim().chars().take(300).collect();
    match code {
        Some(0) => {
            let field = |k: &str| {
                out.split_whitespace()
                    .find_map(|w| w.strip_prefix(k)?.strip_prefix('='))
                    .and_then(|v| v.parse::<u64>().ok())
            };
            match (field("disk"), field("mem")) {
                (Some(d), _) if d < MIN_DISK_MIB => Health::LowDisk(d),
                (Some(_), Some(m)) if m < MIN_MEM_MIB => Health::LowMemory(m),
                (Some(_), Some(_)) => Health::Ok,
                _ => Health::Broken(format!(
                    "unexpected health answer: {:?}",
                    out.trim().chars().take(200).collect::<String>()
                )),
            }
        }
        Some(255) => Health::Unreachable(if err.is_empty() {
            "ssh failed".into()
        } else {
            err
        }),
        Some(c) => Health::Broken(format!("root or a new process failed (exit {c}): {err}")),
        None => Health::Broken(format!("the check was killed by a signal: {err}")),
    }
}

/// What `run` knows when it decides (`verdict`).
struct Situation<'a> {
    health: &'a Health,
    /// Another round is in the VM (holds the lock, waits for it, or runs
    /// `--shared`), or the user holds `vm/root.lock`.
    live: bool,
    /// The disk cleanup already ran since the set of live rounds last changed.
    cleaned: bool,
    /// This run already reset the VM.
    reset_done: bool,
    /// The `--lock-timeout` budget is spent.
    out_of_time: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    /// Healthy: sync and queue for the lock.
    Go,
    /// Short of disk: remove the build caches no round uses, then check again.
    CleanDisk,
    /// Unhealthy and nobody else in the VM: back to the base snapshot.
    Reset,
    /// Unhealthy, but a round is alive: never reset under it (2026-11-13: a
    /// reset killed two rounds midway, both exit 255). Check again later:
    /// load and memory pass when it ends, a slow SSH answers.
    Wait,
    /// Out of time with a round still alive, or unhealthy after a reset.
    GiveUp,
}

/// Reset or wait: the reset only when no round is alive.
fn verdict(s: &Situation) -> Verdict {
    if *s.health == Health::Ok {
        return Verdict::Go;
    }
    if matches!(s.health, Health::LowDisk(_)) && !s.cleaned {
        return Verdict::CleanDisk;
    }
    if s.live {
        return if s.out_of_time {
            Verdict::GiveUp
        } else {
            Verdict::Wait
        };
    }
    if s.reset_done {
        return Verdict::GiveUp;
    }
    Verdict::Reset
}

/// Removes `$root/<worktree>/target` of the worktrees not named after the
/// goal, least recently built first, until `$1` MiB are free; one line per
/// removal, then `vm-lab: <n> MiB free`.
const CLEAN_SH: &str = r#"goal=$1; shift; keep=" $* "
avail() { df --output=avail -m "$root" | tail -1 | tr -d ' '; }
for d in "$root"/*/target; do
  [ -d "$d" ] || continue
  n=${d#"$root"/}; n=${n%/target}
  case "$keep" in *" $n "*) continue ;; esac
  t=$(find "$d" -maxdepth 2 -printf '%T@\n' 2>/dev/null | sort -n | tail -1)
  echo "${t%.*} $d"
done | sort -n | while read -r t d; do
  [ "$(avail)" -ge "$goal" ] && break
  mib=$(du -sm "$d" 2>/dev/null | cut -f1)
  rm -rf "$d" && echo "vm-lab: removed $d (${mib:-?} MiB, last built $(( ($(date +%s) - ${t:-0}) / 60 )) min ago)"
done
echo "vm-lab: $(avail) MiB free in $root"
"#;

/// A round in the VM, seen from this host.
#[derive(Debug, PartialEq, Eq)]
struct LiveRound {
    /// For messages: `/srv/lab/wt (host pid 123, round 123.456)`.
    who: String,
    /// `/srv/lab/<worktree>` (none for the user's `vm/root.lock`).
    dir: Option<String>,
}

impl LiveRound {
    /// The worktree name, what the disk cleanup must leave alone.
    fn name(&self) -> Option<String> {
        self.dir.as_deref().and_then(dir_name)
    }
}

/// `/srv/lab/wt` → `wt`.
fn dir_name(dir: &str) -> Option<String> {
    dir.rsplit('/')
        .next()
        .filter(|n| !n.is_empty())
        .map(str::to_owned)
}

/// The `ssh … sudo env COREROUTER_LAB_ROUND=<round> bash -c <script>` that
/// `run` starts for its round: `(round, /srv/lab/<worktree>)`. The mux
/// master renames itself (`ssh: <path> [mux]`) and rsync's ssh carries no
/// round, so neither counts.
fn round_of_ssh(args: &[String]) -> Option<(String, String, String)> {
    let prog = args.first()?;
    if prog.rsplit('/').next() != Some("ssh") {
        return None;
    }
    let round = args
        .iter()
        .find_map(|a| a.strip_prefix(ROUND_VAR)?.strip_prefix('='))?;
    let dir = args
        .iter()
        .find_map(|a| {
            let (_, rest) = a.split_once("CARGO_TARGET_DIR=")?;
            let path = rest.split_whitespace().next()?;
            path.strip_suffix("/target").map(str::to_owned)
        })
        .unwrap_or_default();
    // Which VM: the ssh's `HostKeyAlias=<name>` (every `vm_lab.rs` since
    // G0.26 sets it).
    let alias = args
        .iter()
        .find_map(|a| a.strip_prefix("HostKeyAlias="))
        .unwrap_or_default();
    Some((round.to_owned(), dir, alias.to_owned()))
}

/// Rounds in the VM started by a live `vm-lab run` of this host (their ssh
/// carries the round mark; `round_alive` rules out a reused pid), other
/// than `own`; plus the user's hand-held `vm/root.lock`. Works with the VM
/// unreachable: it only reads this host's `/proc`.
fn live_rounds(own: &str, host_lock: &Path, vm: &str) -> Vec<LiveRound> {
    let mut live = Vec::new();
    if host_lock_held(host_lock) {
        live.push(LiveRound {
            who: format!("{} (a round the user runs by hand)", host_lock.display()),
            dir: None,
        });
    }
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return live;
    };
    let mut seen = Vec::new();
    for e in entries.flatten() {
        let Ok(cmdline) = std::fs::read(e.path().join("cmdline")) else {
            continue;
        };
        let args: Vec<String> = cmdline
            .split(|b| *b == 0)
            .map(|a| String::from_utf8_lossy(a).into_owned())
            .collect();
        let Some((round, dir, alias)) = round_of_ssh(&args) else {
            continue;
        };
        if alias != vm || round == own || seen.contains(&round) || !round_alive(&round) {
            continue;
        }
        let pid = round.split('.').next().unwrap_or("?");
        let where_ = if dir.is_empty() { "?" } else { dir.as_str() };
        live.push(LiveRound {
            who: format!("{where_} (host pid {pid}, round {round})"),
            dir: (!dir.is_empty()).then(|| dir.clone()),
        });
        seen.push(round);
    }
    live
}

fn live_list(live: &[LiveRound]) -> String {
    live.iter()
        .map(|r| format!("  {}", r.who))
        .collect::<Vec<_>>()
        .join("\n")
}

/// `vm/root.lock` is held by someone other than an ancestor of this process.
fn host_lock_held(host_lock: &Path) -> bool {
    let held = Command::new("flock")
        .args(["-n", "-E", "75"])
        .arg(host_lock)
        .arg("true")
        .stdin(Stdio::null())
        .status()
        .is_ok_and(|s| s.code() == Some(75));
    held && !held_by_ancestor(host_lock)
}

/// `cmd`'s output, or `Ok(None)` when it does not end within `limit` (then
/// it is killed). For short answers: the pipes are read after the exit.
fn output_within(
    cmd: &mut Command,
    limit: Duration,
) -> Result<Option<std::process::Output>, String> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{:?}: {e}", cmd.get_program()))?;
    let deadline = Instant::now() + limit;
    let status = loop {
        if let Some(st) = child.try_wait().map_err(|e| format!("wait: {e}"))? {
            break st;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(None);
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    if let Some(mut o) = child.stdout.take() {
        let _ = o.read_to_end(&mut stdout);
    }
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_end(&mut stderr);
    }
    Ok(Some(std::process::Output {
        status,
        stdout,
        stderr,
    }))
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
    /// Print `quiet::MARKER` once the lock is held (`run --perf`, G0.26d).
    marker: bool,
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
        if r.marker {
            // The host quiets VM 1's CPUs from here (G0.26d), not while the
            // round only waits for the lock.
            s.push_str(&format!("echo {} >&2\n", shell_quote(quiet::MARKER)));
            // …and starts the command once the host says the CPUs are quiet.
            let go = shell_quote(&quiet::go_file(r.id));
            s.push_str(&format!(
                "for i in $(seq {}); do [ -e {go} ] && break; sleep 0.1; done; rm -f {go}\n",
                quiet::GO_WAIT_S * 10
            ));
        }
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

/// `create`'s options: the VM's defaults, overridden; `--from <vm>` clones
/// that VM's base snapshot instead of provisioning from the cloud image.
fn parse_spec(args: &[String], vm: &Vm) -> Result<(Spec, Option<Vm>), String> {
    let mut spec = Spec {
        cpus: vm.cpus,
        memory_mib: vm.memory_mib,
        disk_gib: vm.disk_gib,
        wires: 1,
    };
    let mut from = None;
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let raw = it.next().ok_or_else(|| format!("{flag} needs a value"))?;
        if flag == "--from" {
            let src = Vm::parse(raw)?;
            if src == *vm {
                return Err(format!(
                    "--from {raw}: {} cannot be cloned from itself",
                    vm.name
                ));
            }
            from = Some(src);
            continue;
        }
        let value = raw.parse::<u32>().map_err(|e| format!("{flag}: {e}"))?;
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
    Ok((spec, from))
}

/// `(wire0a, mac), (wire0b, mac), …` for `wires` pairs.
fn wire_nics(wires: u32, mac_prefix: &str) -> Vec<(String, String)> {
    (0..wires)
        .flat_map(|w| {
            [("a", 0), ("b", 1)].map(|(side, n)| {
                (
                    format!("wire{w}{side}"),
                    format!("{mac_prefix}:{:02x}", w * 2 + n),
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

fn exit_like(status: std::process::ExitStatus, vm: &str) -> Result<(), String> {
    if status.success() {
        Ok(())
    } else {
        Err(format!("command in {vm} exited with {status}"))
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

/// `"key": <number>` in a flat JSON text (`qemu-img info --output=json`).
fn json_u64(text: &str, key: &str) -> Option<u64> {
    let (_, rest) = text.split_once(&format!("\"{key}\""))?;
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest.get(..end)?.parse().ok()
}

pub(crate) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// What `vm-lab run` leaves out of the copy of the worktree it sends to the
/// VM (rsync patterns, anchored at the worktree's root). The VM's disk is
/// small (20 GiB until 2026-11-13): build trees never go there.
const SYNC_EXCLUDES: &[&str] = &[
    "--exclude=/target",
    "--exclude=/target-*",
    "--exclude=/vm/",
    "--exclude=/.git",
    // The app copies `.claude/` into each worktree, parked Buildroot trees
    // included (4.2 GB, measured).
    "--exclude=/.claude/",
    "--exclude=/plan/",
    "--exclude=/fuzz/target/",
    // Buildroot's downloads and output trees, a parked one (`os/out.old`,
    // 18 GB, measured) included: the image reaches the VM by `vm-lab put`,
    // never by the sync, and such a tree filled the VM's disk in the middle
    // of the rsync ("error in file IO", 2026-11-12).
    "--exclude=/os/dl/",
    "--exclude=/os/out*/",
    "--exclude=/apps/corerouter-gui/dist/",
    "--exclude=/dist/",
];

#[cfg(test)]
mod tests {
    use super::*;

    /// The real rsync with [`SYNC_EXCLUDES`]: sources go, build trees stay.
    #[test]
    fn sync_leaves_build_trees_out() {
        if Command::new("rsync").arg("--version").output().is_err() {
            eprintln!("rsync not installed: skipped");
            return;
        }
        let tmp = std::env::temp_dir().join(format!("vmlab-sync-{}", std::process::id()));
        let (src, dst) = (tmp.join("src"), tmp.join("dst"));
        let files = [
            "crates/a.rs",
            "os/configs/x_defconfig",
            "os/patches/p.patch",
            "os/dl/pkg/pkg.tar.gz",
            "os/out/build/big",
            "os/out.old/build/big",
            "target/debug/x",
            "target-img/x",
            ".git/HEAD",
        ];
        for f in files {
            let p = src.join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, "x").unwrap();
        }
        std::fs::create_dir_all(&dst).unwrap();
        let ok = Command::new("rsync")
            .arg("-a")
            .args(SYNC_EXCLUDES)
            .arg(format!("{}/", src.display()))
            .arg(&dst)
            .status()
            .unwrap()
            .success();
        let sent: Vec<&str> = files.into_iter().filter(|f| dst.join(f).exists()).collect();
        std::fs::remove_dir_all(&tmp).unwrap();
        assert!(ok);
        assert_eq!(
            sent,
            [
                "crates/a.rs",
                "os/configs/x_defconfig",
                "os/patches/p.patch"
            ]
        );
    }

    #[test]
    fn wires_pair_up_and_never_reuse_a_mac() {
        let first = wire_nics(2, VMS[0].wire_mac_prefix);
        let names: Vec<&str> = first.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["wire0a", "wire0b", "wire1a", "wire1b"]);
        // VM 1 keeps the MACs it had before G0.26c (its netplan matches them).
        assert_eq!(first[0].1, "52:54:00:c0:73:00");
        // Every NIC of every VM, at the most wires, plus the CI runner's.
        let mut macs: Vec<String> = vec![crate::ci_runner::MGMT_MAC.to_owned()];
        for vm in VMS {
            macs.push(vm.mgmt_mac.to_owned());
            macs.extend(
                wire_nics(MAX_WIRES, vm.wire_mac_prefix)
                    .into_iter()
                    .map(|(_, m)| m),
            );
        }
        let before = macs.len();
        macs.sort_unstable();
        macs.dedup();
        assert_eq!(macs.len(), before);
    }

    /// Two VMs at the most wires never bind the same UDP port.
    #[test]
    fn wire_ports_of_the_vms_never_overlap() {
        let ports = |vm: &Vm| {
            let lab = Lab {
                root: "/w/x".into(),
                dir: "/c/vm".into(),
                vm: *vm,
            };
            let (spec, _) = parse_spec(&[], vm).unwrap();
            let xml = lab.domain_xml(
                &Spec {
                    wires: MAX_WIRES,
                    ..spec
                },
                Path::new("/o.qcow2"),
            );
            xml.match_indices("port='")
                .map(|(i, _)| {
                    let rest = &xml[i + 6..];
                    rest[..rest.find('\'').unwrap()].parse::<u16>().unwrap()
                })
                .collect::<std::collections::BTreeSet<u16>>()
        };
        let (a, b) = (ports(&VMS[0]), ports(&VMS[1]));
        assert_eq!(a.len(), 2 * MAX_WIRES as usize);
        assert_eq!(a.first(), Some(&47_210));
        assert!(a.is_disjoint(&b), "{a:?} {b:?}");
    }

    #[test]
    fn wire_ends_point_at_each_other() {
        let lab = Lab {
            root: "/w/x".into(),
            dir: "/c/vm".into(),
            vm: VMS[0],
        };
        let (spec, _) = parse_spec(&[], &VMS[0]).unwrap();
        let xml = lab.domain_xml(&Spec { wires: 1, ..spec }, Path::new("/c/vm/o.qcow2"));
        assert!(xml.contains("port='47211'>\n        <local address='127.0.0.1' port='47210'/>"));
        assert!(xml.contains("port='47210'>\n        <local address='127.0.0.1' port='47211'/>"));
        assert!(xml.contains("<name>corerouter-lab</name>"));
        // The CPU map: vCPU i on host CPU 8+i, QEMU's threads on 24-31.
        assert!(xml.contains("<vcpupin vcpu='0' cpuset='8'/>"));
        assert!(xml.contains("<vcpupin vcpu='7' cpuset='15'/>"));
        assert!(xml.contains("<emulatorpin cpuset='24-31'/>"));
        assert!(xml.contains("freePageReporting='on'"));
    }

    fn strings(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn vms_are_named_by_number_short_or_full_name() {
        for (t, n) in [
            ("1", 1),
            ("lab", 1),
            ("corerouter-lab", 1),
            ("2", 2),
            ("lab2", 2),
            ("corerouter-lab2", 2),
        ] {
            assert_eq!(Vm::parse(t).unwrap().num, n, "{t}");
        }
        for bad in ["3", "", "ci", "corerouter-ci", "lab3"] {
            assert!(Vm::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_front_vm_comes_from_the_flag_then_the_variable() {
        let (vm, rest) = front_vm(&strings(&["status"]), None).unwrap();
        assert_eq!((vm, rest), (None, strings(&["status"])));
        let (vm, rest) = front_vm(&strings(&["--vm", "2", "ssh", "ls"]), None).unwrap();
        assert_eq!((vm, rest), (Some(VMS[1]), strings(&["ssh", "ls"])));
        let (vm, _) = front_vm(&strings(&["--vm=lab2", "status"]), Some("1")).unwrap();
        assert_eq!(vm, Some(VMS[1]), "the flag wins over the variable");
        let (vm, _) = front_vm(&strings(&["status"]), Some("2")).unwrap();
        assert_eq!(vm, Some(VMS[1]));
        let (vm, _) = front_vm(&strings(&["status"]), Some(" ")).unwrap();
        assert_eq!(vm, None, "an empty variable is unset");
        assert!(front_vm(&strings(&["--vm"]), None).is_err());
        assert!(front_vm(&strings(&["status"]), Some("9")).is_err());
        // `--vm` after the subcommand belongs to it (ssh's remote command).
        let (vm, rest) = front_vm(&strings(&["ssh", "--vm", "2"]), None).unwrap();
        assert_eq!((vm, rest.len()), (None, 3));
    }

    #[test]
    fn run_options_parse_as_before_plus_perf_and_vm() {
        // What every caller passed before G0.26c still parses the same way.
        let (o, cmd) = parse_run(&strings(&["--", "cargo", "xtask", "xdp-root"]), None).unwrap();
        assert_eq!(
            o,
            RunOpts {
                sync: true,
                exclusive: true,
                timeout_s: LOCK_TIMEOUT_DEFAULT,
                vm: None,
                perf: false,
                quiet: true
            }
        );
        assert_eq!(cmd, strings(&["cargo", "xtask", "xdp-root"]));
        let (o, cmd) = parse_run(
            &strings(&[
                "--no-sync",
                "--shared",
                "--lock-timeout",
                "1h",
                "--",
                "true",
            ]),
            Some("90s"),
        )
        .unwrap();
        assert_eq!(
            (o.sync, o.exclusive, o.timeout_s, cmd.len()),
            (false, false, 3600, 1)
        );
        let (o, _) = parse_run(&strings(&["--lock-timeout=2m", "true"]), Some("90s")).unwrap();
        assert_eq!(o.timeout_s, 120);
        let (o, _) = parse_run(&strings(&["true"]), Some("90s")).unwrap();
        assert_eq!(o.timeout_s, 90);
        let (o, _) = parse_run(&strings(&["--perf", "--vm", "1", "--", "x"]), None).unwrap();
        assert_eq!((o.perf, o.vm), (true, Some(VMS[0])));
        let (o, _) = parse_run(&strings(&["--perf", "--no-quiet", "--", "x"]), None).unwrap();
        assert_eq!((o.perf, o.quiet), (true, false));
        let (o, _) = parse_run(&strings(&["--vm=2", "--", "x"]), None).unwrap();
        assert_eq!(o.vm, Some(VMS[1]));
        assert!(parse_run(&strings(&["--vm"]), None).is_err());
        assert!(
            parse_run(&strings(&["--perf", "--"]), None).is_err(),
            "nothing to run"
        );
        assert!(parse_run(&strings(&["x"]), Some("forever")).is_err());
    }

    #[test]
    fn perf_is_vm_1_and_a_named_vm_wins() {
        let opts = |vm: Option<Vm>, perf: bool| RunOpts {
            sync: true,
            exclusive: true,
            timeout_s: 1,
            vm,
            perf,
            quiet: true,
        };
        assert_eq!(run_vm(None, &opts(None, false)).unwrap(), None);
        assert_eq!(run_vm(None, &opts(None, true)).unwrap(), Some(VMS[0]));
        assert_eq!(
            run_vm(Some(VMS[1]), &opts(None, false)).unwrap(),
            Some(VMS[1])
        );
        assert_eq!(
            run_vm(None, &opts(Some(VMS[1]), false)).unwrap(),
            Some(VMS[1])
        );
        assert_eq!(
            run_vm(Some(VMS[0]), &opts(Some(VMS[1]), false)).unwrap(),
            Some(VMS[0])
        );
        assert!(run_vm(Some(VMS[1]), &opts(None, true)).is_err());
        assert!(run_vm(None, &opts(Some(VMS[1]), true)).is_err());
        assert_eq!(
            run_vm(Some(VMS[0]), &opts(None, true)).unwrap(),
            Some(VMS[0])
        );
    }

    #[test]
    fn pick_prefers_a_free_vm_2_and_keeps_vm_1_for_measurements() {
        let c = |num: usize, exists: bool, busy: usize| Candidate {
            vm: VMS[num - 1],
            exists,
            busy,
        };
        let n = |cands: &[Candidate], perf: bool| pick(cands, perf).num;
        // Both free: VM 2.
        assert_eq!(n(&[c(1, true, 0), c(2, true, 0)], false), 2);
        // VM 2 busy, VM 1 free: VM 1.
        assert_eq!(n(&[c(1, true, 0), c(2, true, 1)], false), 1);
        // Both busy: the fewest rounds, VM 2 on a tie.
        assert_eq!(n(&[c(1, true, 1), c(2, true, 1)], false), 2);
        assert_eq!(n(&[c(1, true, 1), c(2, true, 3)], false), 1);
        // No VM 2 (before it is created): VM 1, as before G0.26c.
        assert_eq!(n(&[c(1, true, 2), c(2, false, 0)], false), 1);
        assert_eq!(n(&[c(1, false, 0), c(2, false, 0)], false), 1);
        // --perf: VM 1, however busy.
        assert_eq!(n(&[c(1, true, 5), c(2, true, 0)], true), 1);
    }

    /// The CPU map of `docs/vm-lab.md`: nothing else on VM 1's CPUs (its
    /// vCPUs and its QEMU threads); VM 2 inside the CI runner's CCD.
    #[test]
    fn the_measurement_vm_shares_no_cpu() {
        use std::collections::BTreeSet;
        let cpus = |list: &str| -> BTreeSet<u32> {
            list.split(',')
                .flat_map(|r| match r.split_once('-') {
                    Some((a, b)) => (a.parse::<u32>().unwrap()..=b.parse().unwrap()).collect(),
                    None => vec![r.parse().unwrap()],
                })
                .collect()
        };
        let set = |v: &[u32], emu: &str| -> BTreeSet<u32> {
            v.iter().copied().chain(cpus(emu)).collect()
        };
        let vm1 = set(VMS[0].vcpu_cpus, VMS[0].emulator_cpus);
        let vm2 = set(VMS[1].vcpu_cpus, VMS[1].emulator_cpus);
        let ci = set(CI_VCPU_CPUS, CI_EMULATOR_CPUS);
        assert!(vm1.is_disjoint(&vm2), "{vm1:?} {vm2:?}");
        assert!(vm1.is_disjoint(&ci), "{vm1:?} {ci:?}");
        assert!(
            vm1.iter()
                .all(|c| (8..16).contains(c) || (24..32).contains(c)),
            "CCD1"
        );
        assert!(ci.iter().all(|c| *c < 32));
        // One host CPU per vCPU at the default size (no two vCPUs share one).
        for (vcpus, n) in [
            (VMS[0].vcpu_cpus, VMS[0].cpus),
            (VMS[1].vcpu_cpus, VMS[1].cpus),
            (CI_VCPU_CPUS, 16),
        ] {
            let used: BTreeSet<u32> = pin_plan(n, vcpus).into_iter().map(|(_, c)| c).collect();
            assert_eq!(used.len(), n as usize);
        }
        // More vCPUs than the map wraps around instead of failing.
        assert_eq!(pin_plan(6, VMS[1].vcpu_cpus).last(), Some(&(5, 5)));
        assert!(pin_plan(3, &[]).is_empty());
        assert_eq!(cpu_list(VMS[0].vcpu_cpus, 8), "8-15");
        assert_eq!(cpu_list(CI_VCPU_CPUS, 16), "0-7,16-23");
        assert_eq!(cpu_list(&[1, 3, 4], 3), "1,3-4");
        let xml = cputune_xml(16, CI_VCPU_CPUS, CI_EMULATOR_CPUS);
        assert!(xml.contains("<vcpupin vcpu='8' cpuset='16'/>"), "{xml}");
        assert!(xml.contains("<emulatorpin cpuset='0-7,16-23'/>"));
    }

    #[test]
    fn pin_takes_a_lab_vm_or_the_ci_runner() {
        assert_eq!(parse_pin(&[]).unwrap(), (false, None));
        assert_eq!(
            parse_pin(&strings(&["--vm", "1"])).unwrap(),
            (false, Some(PinTarget::Lab(VMS[0])))
        );
        assert_eq!(
            parse_pin(&strings(&["--force", "--vm=ci"])).unwrap(),
            (true, Some(PinTarget::Ci))
        );
        assert_eq!(
            parse_pin(&strings(&["--vm", "corerouter-ci"])).unwrap().1,
            Some(PinTarget::Ci)
        );
        assert!(parse_pin(&strings(&["--vm"])).is_err());
        assert!(parse_pin(&strings(&["--vm", "3"])).is_err());
        assert!(parse_pin(&strings(&["--bogus"])).is_err());
    }

    #[test]
    fn status_says_whether_the_cpu_map_is_applied() {
        let free = " VCPU   CPU Affinity\n----------------------\n 0      0-31\n 1      0-31\n";
        let emu_free =
            "emulator: CPU Affinity\n----------------------------------\n       *: 0-31\n";
        let line = pin_summary(free, emu_free, &[4, 5], "20-23");
        assert!(line.contains("0→0-31 1→0-31"), "{line}");
        assert!(line.contains("vm-lab pin"), "{line}");
        let pinned = " VCPU   CPU Affinity\n----------------------\n 0      4\n 1      5\n";
        let emu = "emulator: CPU Affinity\n----------------------------------\n       *: 20-23\n";
        let line = pin_summary(pinned, emu, &[4, 5], "20-23");
        assert!(line.contains("as in docs/vm-lab.md"), "{line}");
        assert_eq!(vcpu_count("4\n"), Some(4));
        assert_eq!(vcpu_count("current         live      8\n"), Some(8));
    }

    /// VM 1's files are where they were before G0.26c; VM 2 has its own.
    #[test]
    fn each_vm_has_its_own_files_and_shares_the_image_cache() {
        let lab = |vm| Lab {
            root: "/w/x".into(),
            dir: "/c/vm".into(),
            vm,
        };
        let (one, two) = (lab(VMS[0]), lab(VMS[1]));
        for f in [
            "id_ed25519",
            "known_hosts",
            HOST_LOCK,
            HEALTH_LOCK,
            "seed.iso",
        ] {
            assert_eq!(one.path(f), Path::new("/c/vm").join(f));
            assert_eq!(two.path(f), Path::new("/c/vm/corerouter-lab2").join(f));
        }
        assert_eq!(
            one.path("corerouter-lab.qcow2"),
            Path::new("/c/vm/corerouter-lab.qcow2")
        );
        assert_eq!(two.shared("base"), Path::new("/c/vm/base"));
        assert_eq!(two.shared("tools"), one.shared("tools"));
        // The ssh of each VM pins its own host key alias and master socket.
        let args = |l: &Lab| -> Vec<String> {
            l.ssh_base("192.0.2.1")
                .get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect()
        };
        assert!(args(&two).contains(&"HostKeyAlias=corerouter-lab2".to_owned()));
        assert!(args(&two).contains(&"ControlPath=/c/vm/corerouter-lab2/cm-%C".to_owned()));
        assert!(args(&one).contains(&"ControlPath=/c/vm/cm-%C".to_owned()));
        assert!(
            args(&two)
                .iter()
                .any(|a| a.ends_with("/c/vm/corerouter-lab2/known_hosts"))
        );
    }

    #[test]
    fn qemu_img_json_numbers_are_read() {
        let info = r#"{ "virtual-size": 21474836480, "filename": "x", "actual-size": 7 }"#;
        assert_eq!(json_u64(info, "virtual-size"), Some(21_474_836_480));
        assert_eq!(json_u64(info, "actual-size"), Some(7));
        assert_eq!(json_u64(info, "missing"), None);
        assert_eq!(json_u64(r#"{"virtual-size": "x"}"#, "virtual-size"), None);
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
            mgmt_ipv4(table, VMS[0].mgmt_mac).as_deref(),
            Some("192.168.122.47")
        );
        assert_eq!(
            mgmt_ipv4(" Name MAC Protocol Address\n", VMS[0].mgmt_mac),
            None
        );
        // VM 2's NIC is another row.
        assert_eq!(mgmt_ipv4(table, VMS[1].mgmt_mac), None);
    }

    #[test]
    fn spec_flags_are_checked() {
        let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let (s, from) = parse_spec(&args(&["--cpus", "16", "--wires", "2"]), &VMS[0]).unwrap();
        assert_eq!((s.cpus, s.wires, s.memory_mib, from), (16, 2, 16_384, None));
        assert!(parse_spec(&args(&["--wires", "9"]), &VMS[0]).is_err());
        assert!(parse_spec(&args(&["--cpus"]), &VMS[0]).is_err());
        assert!(parse_spec(&args(&["--bogus", "1"]), &VMS[0]).is_err());
        // VM 2's own defaults, and the clone source.
        let (s, from) = parse_spec(&args(&["--from", "1"]), &VMS[1]).unwrap();
        assert_eq!((s.cpus, s.memory_mib, s.disk_gib), (4, 6_144, 30));
        assert_eq!(from, Some(VMS[0]));
        assert!(parse_spec(&args(&["--from", "2"]), &VMS[1]).is_err());
        assert!(parse_spec(&args(&["--from", "9"]), &VMS[1]).is_err());
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
            marker: false,
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
        // The quiet marker (G0.26d) only when asked, after the lock.
        assert!(!s.contains(quiet::MARKER));
        let m = round_script(&Round {
            marker: true,
            ..round(LOCK, "/srv/lab/w", "x", 9)
        });
        let (lock_at, marker_at) = (
            m.find("flock -w 9 9").unwrap(),
            m.find(quiet::MARKER).unwrap(),
        );
        let go_at = m
            .find("[ -e /run/corerouter-lab.quiet.4242.77 ] && break")
            .unwrap();
        assert!(lock_at < marker_at && marker_at < go_at);
        assert!(go_at < m.find("( cd /srv/lab/w/src").unwrap());
        assert!(m.contains("$(seq 150)"), "waits at most 15 s");
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

    fn every_situation() -> Vec<(Health, bool, bool, bool, bool)> {
        let healths = [
            Health::Ok,
            Health::LowDisk(1500),
            Health::LowMemory(700),
            Health::Broken("exit 11".into()),
            Health::Unreachable("timeout".into()),
        ];
        let mut all = Vec::new();
        for h in healths {
            for bits in 0..16u8 {
                all.push((
                    h.clone(),
                    bits & 1 != 0,
                    bits & 2 != 0,
                    bits & 4 != 0,
                    bits & 8 != 0,
                ));
            }
        }
        all
    }

    fn decide(h: &Health, live: bool, cleaned: bool, reset_done: bool, late: bool) -> Verdict {
        verdict(&Situation {
            health: h,
            live,
            cleaned,
            reset_done,
            out_of_time: late,
        })
    }

    /// 2026-11-13: a `run` found the disk short while another round was
    /// building and reset the VM under it (both rounds exit 255).
    #[test]
    fn a_live_round_is_never_reset() {
        for (h, live, cleaned, reset_done, late) in every_situation() {
            let v = decide(&h, live, cleaned, reset_done, late);
            if live {
                assert_ne!(v, Verdict::Reset, "{h:?} cleaned={cleaned} late={late}");
            }
            if h == Health::Ok {
                assert_eq!(v, Verdict::Go);
            }
        }
    }

    #[test]
    fn unhealthy_under_a_live_round_waits_then_gives_up() {
        for h in [
            Health::LowMemory(700),
            Health::Broken("exit 11".into()),
            Health::Unreachable("no answer by SSH in 180 s".into()),
            Health::LowDisk(1500),
        ] {
            assert_eq!(decide(&h, true, true, false, false), Verdict::Wait, "{h:?}");
            assert_eq!(
                decide(&h, true, true, false, true),
                Verdict::GiveUp,
                "{h:?}"
            );
        }
    }

    #[test]
    fn unhealthy_and_alone_resets_once() {
        for h in [
            Health::LowMemory(700),
            Health::Broken("exit 11".into()),
            Health::Unreachable("x".into()),
        ] {
            assert_eq!(
                decide(&h, false, false, false, false),
                Verdict::Reset,
                "{h:?}"
            );
            assert_eq!(
                decide(&h, false, false, true, false),
                Verdict::GiveUp,
                "{h:?}"
            );
        }
    }

    #[test]
    fn short_disk_cleans_before_anything_else() {
        let low = Health::LowDisk(1500);
        for live in [false, true] {
            assert_eq!(decide(&low, live, false, false, false), Verdict::CleanDisk);
        }
        // Cleaned and still short: reset alone, wait under a round.
        assert_eq!(decide(&low, false, true, false, false), Verdict::Reset);
        assert_eq!(decide(&low, true, true, false, false), Verdict::Wait);
    }

    #[test]
    fn health_answers_are_classified() {
        assert_eq!(classify(Some(0), "disk=9000 mem=12000\n", ""), Health::Ok);
        assert_eq!(
            classify(Some(0), "disk=181 mem=12000", ""),
            Health::LowDisk(181)
        );
        assert_eq!(
            classify(Some(0), "disk=9000 mem=512", ""),
            Health::LowMemory(512)
        );
        assert!(matches!(classify(Some(0), "", ""), Health::Broken(_)));
        assert!(matches!(
            classify(Some(255), "", "Connection timed out during banner exchange"),
            Health::Unreachable(w) if w.contains("banner")
        ));
        assert!(matches!(classify(Some(11), "", ""), Health::Broken(w) if w.contains("exit 11")));
        assert!(
            matches!(classify(Some(1), "", "sudo: a password is required"), Health::Broken(w) if w.contains("sudo"))
        );
        assert!(matches!(classify(None, "", ""), Health::Broken(_)));
        assert!(Health::LowDisk(181).to_string().contains("181 MiB free"));
    }

    #[test]
    fn health_script_answers_on_this_machine() {
        let dir = std::env::temp_dir();
        let script = health_script().replace(LAB_ROOT, &dir.to_string_lossy());
        let out = Command::new("bash").args(["-c", &script]).output().unwrap();
        let h = classify(
            out.status.code(),
            &String::from_utf8_lossy(&out.stdout),
            &String::from_utf8_lossy(&out.stderr),
        );
        assert!(
            matches!(h, Health::Ok | Health::LowDisk(_) | Health::LowMemory(_)),
            "{h:?}"
        );
    }

    #[test]
    fn rounds_are_read_from_their_ssh_command_line() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let round = a(&[
            "ssh",
            "-F",
            "/dev/null",
            "-o",
            "HostKeyAlias=corerouter-lab2",
            "lab@192.168.122.46",
            "sudo",
            "env",
            "COREROUTER_LAB_ROUND=1194199.9140753",
            "bash",
            "-c",
            "'if [ ! -r x ]; then exit 1; fi . x export CARGO_TARGET_DIR=/srv/lab/img-443646f1/target CARGO_TERM_COLOR=always'",
        ]);
        assert_eq!(
            round_of_ssh(&round),
            Some((
                "1194199.9140753".into(),
                "/srv/lab/img-443646f1".into(),
                "corerouter-lab2".into()
            ))
        );
        // The ControlPersist master, rsync's ssh, and the shell that started
        // `vm-lab run` (its text mentions the variable) are not rounds.
        let mux = a(&["ssh: /home/oem/code/CoreRouter/vm/cm-fc97 [mux]"]);
        let rsync = a(&[
            "ssh",
            "-F",
            "/dev/null",
            "lab@192.168.122.46",
            "rsync",
            "--server",
        ]);
        let shell = a(&["/bin/bash", "-c", "env COREROUTER_LAB_ROUND=1.2 ssh x"]);
        for other in [mux, rsync, shell] {
            assert_eq!(round_of_ssh(&other), None, "{other:?}");
        }
        assert_eq!(dir_name("/srv/lab/wt").as_deref(), Some("wt"));
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

        /// `CLEAN_SH` on a fake `/srv/lab`: the oldest caches go first, the
        /// kept ones and the sources stay.
        #[test]
        fn disk_cleanup_spares_live_rounds_and_sources() {
            let root = scratch("clean");
            for (name, age_min) in [("old", 300), ("mid", 100), ("live", 500), ("own", 400)] {
                let t = root.join(name).join("target/debug");
                std::fs::create_dir_all(&t).unwrap();
                std::fs::create_dir_all(root.join(name).join("src")).unwrap();
                std::fs::write(t.join("bin"), b"x").unwrap();
                let when = format!("@{}", unix_now() - age_min * 60);
                for p in [t.join("bin"), t.clone(), root.join(name).join("target")] {
                    assert!(
                        Command::new("touch")
                            .arg("-d")
                            .arg(&when)
                            .arg(&p)
                            .status()
                            .unwrap()
                            .success()
                    );
                }
            }
            let run = |goal: &str| {
                let out = Command::new("bash")
                    .arg("-c")
                    .arg(format!("root={}\n{CLEAN_SH}", root.display()))
                    .args(["clean", goal, "live", "own"])
                    .output()
                    .unwrap();
                assert!(out.status.success(), "{out:?}");
                String::from_utf8_lossy(&out.stdout).into_owned()
            };
            // Room enough: nothing goes.
            let out = run("0");
            assert!(!out.contains("removed"), "{out}");
            assert!(out.contains("MiB free in"), "{out}");
            // Never enough: every cache but the kept ones, oldest first.
            let out = run("999999999");
            let removed: Vec<&str> = out.lines().filter(|l| l.contains("removed")).collect();
            assert_eq!(removed.len(), 2, "{out}");
            assert!(removed[0].contains("/old/target"), "{out}");
            assert!(removed[1].contains("/mid/target"), "{out}");
            for name in ["old", "mid"] {
                assert!(!root.join(name).join("target").exists());
                assert!(root.join(name).join("src").exists());
            }
            for name in ["live", "own"] {
                assert!(root.join(name).join("target/debug/bin").exists());
            }
            let _ = std::fs::remove_dir_all(&root);
        }

        /// A process shaped like a round's ssh (bash renamed `ssh`) whose
        /// round mark is this test's own, live, process.
        #[test]
        fn live_rounds_finds_a_round_ssh_on_this_host() {
            if !have_tools() {
                eprintln!("skip: no bash/flock");
                return;
            }
            let d = scratch("live");
            let ssh = d.join("ssh");
            let bash = Command::new("bash")
                .args(["-c", "command -v bash"])
                .output()
                .unwrap();
            std::os::unix::fs::symlink(String::from_utf8_lossy(&bash.stdout).trim(), &ssh).unwrap();
            let me = own_round();
            let mut fake = Command::new(&ssh)
                // Two commands: a single one would be exec'd, losing the argv.
                .args(["-c", "sleep 30; true", "x"])
                .arg(format!("{ROUND_VAR}={me}"))
                .arg("export CARGO_TARGET_DIR=/srv/lab/fake-wt/target CARGO_TERM_COLOR=always")
                .arg("HostKeyAlias=corerouter-lab2")
                .spawn()
                .unwrap();
            let host_lock = d.join("root.lock");
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut found = Vec::new();
            while Instant::now() < deadline {
                found = live_rounds("someone-else", &host_lock, "corerouter-lab2");
                if found.iter().any(|r| r.name().as_deref() == Some("fake-wt")) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            // Its own round is never "another" round, and a round in VM 2
            // is not one in VM 1.
            let own = live_rounds(&me, &host_lock, "corerouter-lab2");
            let in_vm1 = live_rounds("someone-else", &host_lock, "corerouter-lab");
            let _ = fake.kill();
            let _ = fake.wait();
            let _ = std::fs::remove_dir_all(&d);
            let ours = found
                .iter()
                .find(|r| r.name().as_deref() == Some("fake-wt"));
            let ours = ours.unwrap_or_else(|| panic!("not found: {found:?}"));
            assert!(ours.who.contains(&format!("round {me}")), "{ours:?}");
            assert!(!own.iter().any(|r| r.name().as_deref() == Some("fake-wt")));
            assert!(
                !in_vm1
                    .iter()
                    .any(|r| r.name().as_deref() == Some("fake-wt"))
            );
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

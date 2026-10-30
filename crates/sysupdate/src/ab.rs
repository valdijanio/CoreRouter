//! The A/B operations over a [`Platform`]: status, install into the
//! inactive slot, trial boot, confirmation, the boot-time decision of
//! `corerouter-init`, and a scrub of a slot against its signed manifest.
//!
//! The order of the steps is what makes a power cut at any point safe:
//!
//! 1. the target slot leaves `BootOrder` and loses its header (it is no
//!    longer a fallback while it is half written);
//! 2. kernel and rootfs are streamed and hashed, then the rootfs is read
//!    back and its verity tree recomputed (what is on the disk is what was
//!    signed);
//! 3. the header is written, then the slot's `Boot####` (command line with
//!    the verity table and the tuning parameters);
//! 4. the configuration is snapshotted and the trial recorded;
//! 5. `BootNext` — from here the next boot is the trial, once.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde_json::{Value, json};

use crate::efi::{LoadOption, Partition, Vars, boot_name};
use crate::package::{self, Header, Key, Manifest};
use crate::state::{self, Confirm, Outcome, Reason, State, Trial};
use crate::{SlotCmdline, SlotId, cmdline_value, verity};

/// Rows of `config_space.usage` in the status.
pub const CONFIG_USAGE_ROWS: usize = 8;

/// G1.6u: room in `/config` — free bytes, what the next snapshot needs,
/// and what takes room (biggest first, at most [`CONFIG_USAGE_ROWS`]).
fn config_space(config: &Path, usage: Vec<state::Use>) -> Value {
    let rows = usage.len();
    json!({
        "free": state::free_bytes(config),
        "snapshot_need": state::snapshot_need(config).ok(),
        "usage": usage.into_iter().take(CONFIG_USAGE_ROWS).collect::<Vec<_>>(),
        "usage_rows": rows,
    })
}

/// A slot's partition.
#[derive(Debug, Clone)]
pub struct SlotDev {
    pub path: PathBuf,
    pub partuuid: String,
    pub size: u64,
}

/// Everything the operations touch.
#[derive(Debug, Clone)]
pub struct Platform {
    pub vars: Vars,
    /// Where the ESP is (mounted read-only on the router; remounted
    /// read-write around a write).
    pub esp_dir: PathBuf,
    pub esp_remount: bool,
    pub esp: Partition,
    pub slots: [SlotDev; 2],
    pub keys: Vec<Key>,
    /// `/config`.
    pub config: PathBuf,
    /// The running kernel command line.
    pub cmdline: String,
    /// A directory standing in for the router (virtual lab).
    pub lab: Option<PathBuf>,
}

/// What an install, clone or downgrade is asked to do.
#[derive(Debug, Clone)]
pub struct Opts {
    pub reason: Reason,
    pub confirm: Confirm,
    pub timeout_s: u64,
    pub tuning: Vec<(String, String)>,
    pub mgmt: Vec<String>,
    pub now: u64,
    /// Read/hash on one thread, write on another.
    pub pipelined: bool,
    /// Threads for the verity read-back.
    pub threads: usize,
    /// Configuration format the running daemon writes.
    pub config_format: u32,
    pub drill: bool,
}

/// How long each step took (the numbers `system.package.print` shows).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Report {
    pub slot: Option<SlotId>,
    pub version: String,
    pub bytes: u64,
    pub write_ms: u64,
    pub verify_ms: u64,
    pub total_ms: u64,
    pub snapshot_ms: u64,
    pub copied: bool,
    pub cmdline: String,
}

impl Report {
    pub fn json(&self) -> Value {
        json!({
            "slot": self.slot.map(SlotId::as_str),
            "version": self.version,
            "bytes": self.bytes,
            "write_ms": self.write_ms,
            "verify_ms": self.verify_ms,
            "snapshot_ms": self.snapshot_ms,
            "total_ms": self.total_ms,
            "copied": self.copied,
            "cmdline": self.cmdline,
        })
    }
}

fn idx(s: SlotId) -> usize {
    match s {
        SlotId::A => 0,
        SlotId::B => 1,
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The `Boot####` of each slot, recognised by description.
pub fn entries(vars: &Vars) -> [Option<u16>; 2] {
    let mut out = [None, None];
    for n in vars.boot_numbers() {
        if let Some(o) = vars.load_option(n) {
            for s in SlotId::ALL {
                if o.description == s.label()
                    && let Some(e) = out.get_mut(idx(s))
                    && e.is_none()
                {
                    *e = Some(n);
                }
            }
        }
    }
    out
}

/// The slot the firmware boots by default: the first of ours in `BootOrder`.
pub fn primary(vars: &Vars) -> Option<SlotId> {
    let e = entries(vars);
    vars.boot_order().ok()?.into_iter().find_map(|n| {
        SlotId::ALL
            .into_iter()
            .find(|s| e.get(idx(*s)).copied().flatten() == Some(n))
    })
}

/// The slot booted, from the command line: `corerouter.slot=` (a boot
/// entry's), else the built-in `root=PARTUUID=` (the fallback path).
pub fn running_slot(cmdline: &str, partuuids: [&str; 2]) -> Option<SlotId> {
    if let Some(s) = cmdline_value(cmdline, "corerouter.slot") {
        return SlotId::parse(&s);
    }
    let root = cmdline_value(cmdline, "root")?;
    let uuid = root.strip_prefix("PARTUUID=")?;
    SlotId::ALL.into_iter().find(|s| {
        partuuids
            .get(idx(*s))
            .is_some_and(|p| p.eq_ignore_ascii_case(uuid))
    })
}

/// The partitions `running_slot` can tell apart without reading the GPT:
/// the built-in command line names slot A's; a boot entry always says
/// `corerouter.slot=`.
pub fn fallback_partuuids() -> [&'static str; 2] {
    let a = crate::BUILTIN_CMDLINE
        .split_whitespace()
        .find_map(|w| w.strip_prefix("root=PARTUUID="))
        .unwrap_or("");
    [a, ""]
}

/// What `corerouter-init` does about the trial at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Boot {
    Normal,
    /// This is the trial: reboot unless confirmed within `timeout_s`.
    Trial {
        slot: SlotId,
        from: SlotId,
        timeout_s: u64,
    },
}

/// The boot-time step, run by init before the daemon starts: marks the
/// trial booted (and puts a downgrade's configuration in place), or — back
/// on the previous slot — records the failed trial and restores the
/// configuration it ran with. Returns what to do and lines for the console.
pub fn at_boot(
    config: &Path,
    vars: &Vars,
    cmdline: &str,
    partuuids: [&str; 2],
) -> (Boot, Vec<String>) {
    let dir = config.join(state::DIR);
    let (mut st, err) = State::load(&dir);
    let mut log: Vec<String> = err.into_iter().collect();
    let Some(mut t) = st.trial.clone() else {
        return (Boot::Normal, log);
    };
    let running = running_slot(cmdline, partuuids);
    let prim = primary(vars);
    let ents = entries(vars);
    let trial_entry = ents.get(idx(t.slot)).copied().flatten();
    let next = vars.boot_next();
    let now = now_unix();
    if running == Some(t.slot) && prim != Some(t.slot) {
        if next.is_some() && next == trial_entry {
            // A firmware that keeps BootNext would boot the trial forever.
            let _ = vars.remove("BootNext");
            log.push("BootNext was still set after the trial boot: removed".into());
        }
        if !t.booted {
            t.booted = true;
            if let Some(swap) = t.config_swap.clone() {
                match state::restore(config, &swap) {
                    Ok(n) => log.push(format!(
                        "configuration of slot {} put in place ({n} files from {swap})",
                        t.slot.as_str()
                    )),
                    Err(e) => log.push(format!("configuration swap failed: {e}")),
                }
            }
            st.trial = Some(t.clone());
            if let Err(e) = st.save(&dir) {
                log.push(format!("state: {e}"));
            }
        }
        log.push(format!(
            "trial boot of slot {} ({}): confirm within {} s or slot {} boots again",
            t.slot.as_str(),
            t.version,
            t.timeout_s,
            t.from.as_str()
        ));
        return (
            Boot::Trial {
                slot: t.slot,
                from: t.from,
                timeout_s: t.timeout_s,
            },
            log,
        );
    }
    if running == Some(t.slot) {
        // Confirmed, the state write did not happen (power cut).
        st.trial = None;
        st.failed.remove(&t.slot);
        st.last = Some(Outcome {
            result: "confirmed".into(),
            slot: t.slot,
            version: t.version.clone(),
            at_unix: now,
            detail: "confirmed (state completed at boot)".into(),
            stats: t.stats.clone(),
        });
    } else {
        let detail = if next.is_some() && next == trial_entry {
            let _ = vars.remove("BootNext");
            "the firmware did not boot BootNext: this box cannot run a trial boot".to_owned()
        } else if t.booted {
            format!(
                "slot {} booted but was not confirmed within {} s",
                t.slot.as_str(),
                t.timeout_s
            )
        } else {
            format!(
                "slot {} did not come up (kernel, root or init failed)",
                t.slot.as_str()
            )
        };
        log.push(format!(
            "back on slot {} after the trial of slot {} failed: {detail}",
            t.from.as_str(),
            t.slot.as_str()
        ));
        if let Some(b) = &t.config_backup {
            match state::restore(config, b) {
                Ok(n) => log.push(format!("configuration restored from {b} ({n} files)")),
                Err(e) => log.push(format!("configuration restore failed: {e}")),
            }
        }
        st.failed.insert(t.slot, detail.clone());
        st.last = Some(Outcome {
            result: "rolled-back".into(),
            slot: t.slot,
            version: t.version.clone(),
            at_unix: now,
            detail,
            stats: t.stats.clone(),
        });
        st.trial = None;
    }
    if let Err(e) = st.save(&dir) {
        log.push(format!("state: {e}"));
    }
    (Boot::Normal, log)
}

impl Platform {
    fn dev(&self, s: SlotId) -> Result<&SlotDev, String> {
        self.slots.get(idx(s)).ok_or_else(|| "no such slot".into())
    }

    fn partuuids(&self) -> [&str; 2] {
        [
            self.slots
                .first()
                .map(|d| d.partuuid.as_str())
                .unwrap_or(""),
            self.slots.get(1).map(|d| d.partuuid.as_str()).unwrap_or(""),
        ]
    }

    pub fn state_dir(&self) -> PathBuf {
        self.config.join(state::DIR)
    }

    pub fn running(&self) -> Option<SlotId> {
        running_slot(&self.cmdline, self.partuuids())
    }

    /// The slot's header on the ESP, and whether a trusted key signed it.
    pub fn header(&self, s: SlotId) -> Option<(Header, Result<String, String>)> {
        let mut f = File::open(self.esp_dir.join(s.header_file())).ok()?;
        match Header::read(&mut f) {
            Ok(h) => {
                let v = h.verify(&self.keys).map(Key::id_hex);
                Some((h, v))
            }
            Err(_) => None,
        }
    }

    fn verified_header(&self, s: SlotId) -> Result<Header, String> {
        let (h, v) = self
            .header(s)
            .ok_or_else(|| format!("slot {} holds no image", s.as_str()))?;
        v.map_err(|e| format!("slot {}: {e}", s.as_str()))?;
        Ok(h)
    }

    /// Is the running root the dm-verity device built from the running
    /// slot's signed root hash?
    pub fn running_verified(&self) -> bool {
        let Some(s) = self.running() else {
            return false;
        };
        let Ok(h) = self.verified_header(s) else {
            return false;
        };
        cmdline_value(&self.cmdline, "root").as_deref() == Some("/dev/dm-0")
            && cmdline_value(&self.cmdline, "dm-mod.create")
                .is_some_and(|t| t.contains(&h.manifest.rootfs.root_hash))
    }

    /// Runs `f` with the ESP writable.
    fn esp_rw<T>(&self, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
        #[cfg(target_os = "linux")]
        if self.esp_remount {
            use rustix::mount::{MountFlags, mount_remount};
            mount_remount(
                &self.esp_dir,
                MountFlags::NOEXEC | MountFlags::NOSUID | MountFlags::NODEV,
                "",
            )
            .map_err(|e| format!("ESP: remount read-write: {e}"))?;
            let out = f();
            rustix::fs::sync();
            let ro = mount_remount(
                &self.esp_dir,
                MountFlags::RDONLY | MountFlags::NOEXEC | MountFlags::NOSUID | MountFlags::NODEV,
                "",
            );
            return match (out, ro) {
                (Err(e), _) => Err(e),
                (Ok(_), Err(e)) => Err(format!("ESP: remount read-only: {e}")),
                (Ok(v), Ok(())) => Ok(v),
            };
        }
        f()
    }

    /// The status `system.package.print` shows.
    pub fn status(&self, st: &State) -> Value {
        let running = self.running();
        let prim = primary(&self.vars);
        let ents = entries(&self.vars);
        let next_n = self.vars.boot_next();
        let slots: Vec<Value> = SlotId::ALL
            .into_iter()
            .map(|s| {
                let dev = self.dev(s).ok();
                let entry = ents.get(idx(s)).copied().flatten();
                let opt = entry.and_then(|n| self.vars.load_option(n));
                let hdr = self.header(s);
                let trial = st.trial.as_ref().is_some_and(|t| t.slot == s);
                let failed = st.failed.get(&s).cloned();
                let (state, detail) = match (&hdr, running == Some(s)) {
                    (_, true) if trial => ("trial", None),
                    (_, true) => ("running", None),
                    (None, _) => ("empty", None),
                    (Some((_, Err(e))), _) => ("invalid", Some(e.clone())),
                    _ if trial => ("trial", None),
                    _ if failed.is_some() => ("failed", failed.clone()),
                    _ => ("standby", None),
                };
                let m = hdr.as_ref().map(|(h, _)| &h.manifest);
                json!({
                    "slot": s.as_str(),
                    "partition": s.partition(),
                    "size": dev.map(|d| d.size),
                    "state": state,
                    "detail": detail,
                    "running": running == Some(s),
                    "primary": prim == Some(s),
                    "next": next_n.is_some() && next_n == entry,
                    "version": m.map(|m| m.version.clone()),
                    "build": m.map(|m| m.build),
                    "commit": m.map(|m| m.commit.clone()),
                    "channel": m.map(|m| m.channel.clone()),
                    "kernel": m.map(|m| m.kernel_version.clone()),
                    "config_format": m.map(|m| m.config_format),
                    "rootfs_size": m.map(|m| m.rootfs.size),
                    "kernel_size": m.map(|m| m.kernel.size),
                    "root_hash": m.map(|m| m.rootfs.root_hash.clone()),
                    "signed_by": hdr.as_ref().and_then(|(_, v)| v.as_ref().ok().cloned()),
                    "verified": hdr.as_ref().is_some_and(|(_, v)| v.is_ok()),
                    "verity": running == Some(s) && self.running_verified(),
                    "boot_entry": entry.map(boot_name),
                    "cmdline": opt.map(|o| o.cmdline),
                })
            })
            .collect();
        let usage = state::usage(&self.config);
        let snapshots: Vec<Value> = SlotId::ALL
            .into_iter()
            .filter_map(|s| {
                let (name, _) = state::snapshot_dir(&self.config, s);
                let m = state::snapshot_meta(&self.config, &name)?;
                let own = usage
                    .iter()
                    .find(|u| u.path == format!("{}/{name}", state::DIR))
                    .map_or(0, |u| u.bytes);
                Some(json!({"name": name, "slot": s.as_str(), "version": m.version,
                    "format_version": m.format_version, "at_unix": m.at_unix, "files": m.files, "bytes": m.bytes,
                    "own_bytes": own}))
            })
            .collect();
        let partials: Vec<Value> = usage
            .iter()
            .filter(|u| u.kind == "partial")
            .map(|u| json!({"name": u.path.trim_start_matches(&format!("{}/", state::DIR)), "own_bytes": u.bytes}))
            .collect();
        let config_space = config_space(&self.config, usage);
        json!({
            "supported": true,
            "lab": self.lab.is_some(),
            "running": running.map(SlotId::as_str),
            "primary": prim.map(SlotId::as_str),
            "fallback": running.is_some() && prim.is_some() && running != prim && st.trial.is_none(),
            "slots": slots,
            "trial": st.trial.as_ref().map(|t| json!({
                "slot": t.slot.as_str(), "from": t.from.as_str(), "version": t.version,
                "reason": t.reason, "confirm": t.confirm, "timeout_s": t.timeout_s,
                "started_unix": t.started_unix, "booted": t.booted, "mgmt": t.mgmt, "stats": t.stats,
                "config_backup": t.config_backup, "config_swap": t.config_swap,
            })),
            "last": st.last.as_ref().map(|o| json!({
                "result": o.result, "slot": o.slot.as_str(), "version": o.version,
                "at_unix": o.at_unix, "detail": o.detail, "stats": o.stats,
            })),
            "snapshots": snapshots,
            "partials": partials,
            "config_space": config_space,
            "keys": self.keys.iter().map(Key::id_hex).collect::<Vec<_>>(),
        })
    }

    /// The snapshots a trial in progress needs (never removed).
    fn protected_snapshots(&self) -> Vec<String> {
        let (st, _) = State::load(&self.state_dir());
        st.trial
            .map(|t| t.config_backup.into_iter().chain(t.config_swap).collect())
            .unwrap_or_default()
    }

    /// `system.package.snapshot.remove` (G1.6u): see [`state::remove`].
    pub fn remove_snapshots(
        &self,
        names: &[String],
        all: bool,
        dry_run: bool,
    ) -> Result<Value, String> {
        let protected = self.protected_snapshots();
        let r = state::remove(&self.config, names, all, &protected, dry_run)?;
        let freed: u64 = r.iter().filter(|x| x.kept.is_none()).map(|x| x.bytes).sum();
        Ok(json!({"dry_run": dry_run, "snapshots": r, "freed": freed,
            "free": state::free_bytes(&self.config)}))
    }

    /// Makes sure each slot holding a signed image has its boot entry and
    /// that `BootOrder` starts with the running slot then the other (first
    /// boot of an image written with `dd`, or after the NVRAM was cleared).
    /// Without a trial, a running slot that is not the primary means the
    /// firmware skipped the primary: it becomes the running one.
    pub fn provision(&self, tuning_keys: &[&str]) -> Result<Vec<String>, String> {
        let mut log = Vec::new();
        let Some(running) = self.running() else {
            return Ok(log);
        };
        let (st, _) = State::load(&self.state_dir());
        let mut ents = entries(&self.vars);
        for s in SlotId::ALL {
            if ents.get(idx(s)).copied().flatten().is_some() {
                continue;
            }
            let Ok(h) = self.verified_header(s) else {
                continue;
            };
            let tuning = crate::tuning_of(&self.cmdline, tuning_keys);
            let n = self.write_entry(s, &h.manifest, &tuning, false)?;
            if let Some(e) = ents.get_mut(idx(s)) {
                *e = Some(n);
            }
            log.push(format!("created {} for slot {}", boot_name(n), s.as_str()));
        }
        let prim = primary(&self.vars);
        if st.trial.is_none() && prim != Some(running) {
            self.set_order(running, &ents)?;
            log.push(match prim {
                Some(p) => format!(
                    "slot {} did not boot: slot {} is the default now",
                    p.as_str(),
                    running.as_str()
                ),
                None => format!("BootOrder starts with slot {}", running.as_str()),
            });
        }
        Ok(log)
    }

    /// `BootOrder` = `first`, the other slot, then everything else.
    fn set_order(&self, first: SlotId, ents: &[Option<u16>; 2]) -> Result<(), String> {
        let ours: Vec<u16> = [first, first.other()]
            .into_iter()
            .filter_map(|s| ents.get(idx(s)).copied().flatten())
            .filter(|n| self.vars.load_option(*n).is_some())
            .collect();
        let mut order = ours.clone();
        for n in self.vars.boot_order().unwrap_or_default() {
            if !order.contains(&n) && !ents.contains(&Some(n)) {
                order.push(n);
            }
        }
        self.vars
            .set_u16_list("BootOrder", &order)
            .map_err(|e| format!("BootOrder: {e}"))
    }

    /// Takes slot `s` out of `BootOrder` (keeps its entry number).
    fn detach(&self, s: SlotId) -> Result<(), String> {
        let ents = entries(&self.vars);
        let Some(n) = ents.get(idx(s)).copied().flatten() else {
            return Ok(());
        };
        let order: Vec<u16> = self
            .vars
            .boot_order()
            .unwrap_or_default()
            .into_iter()
            .filter(|x| *x != n)
            .collect();
        self.vars
            .set_u16_list("BootOrder", &order)
            .map_err(|e| format!("BootOrder: {e}"))?;
        if self.vars.boot_next() == Some(n) {
            let _ = self.vars.remove("BootNext");
        }
        Ok(())
    }

    fn write_entry(
        &self,
        s: SlotId,
        m: &Manifest,
        tuning: &[(String, String)],
        drill: bool,
    ) -> Result<u16, String> {
        let dev = self.dev(s)?;
        let cmdline = SlotCmdline {
            slot: s,
            partuuid: &dev.partuuid,
            manifest: m,
            tuning,
            running: &self.cmdline,
            drill,
        }
        .render();
        let opt = LoadOption {
            active: true,
            description: s.label().into(),
            partition: Some(self.esp.clone()),
            file: Some(s.efi_path()),
            cmdline,
        };
        let ents = entries(&self.vars);
        let used = self.vars.boot_numbers();
        let n = match ents.get(idx(s)).copied().flatten() {
            Some(n) => n,
            None => (0..=0xffffu16)
                .find(|n| !used.contains(n))
                .ok_or("no free Boot#### number")?,
        };
        self.vars
            .set(&boot_name(n), &opt.encode()?)
            .map_err(|e| format!("{}: {e}", boot_name(n)))?;
        Ok(n)
    }

    fn check_no_trial(&self) -> Result<State, String> {
        let (st, err) = State::load(&self.state_dir());
        if let Some(e) = err {
            return Err(format!("update state unreadable: {e}"));
        }
        if let Some(t) = &st.trial {
            return Err(format!(
                "a trial boot of slot {} is pending: confirm it or let it roll back first",
                t.slot.as_str()
            ));
        }
        Ok(st)
    }

    /// Installs the package at `path` into the inactive slot and arms its
    /// trial boot. `downgrade`: the package must be older than the running
    /// image (and newer or equal otherwise).
    pub fn install(
        &self,
        path: &Path,
        downgrade: bool,
        o: &Opts,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<Report, String> {
        self.check_no_trial()?;
        let mut f = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let meta = f.metadata().map_err(|e| e.to_string())?;
        // A file holds exactly the package; a block device (a USB stick, a
        // test disk) may hold more after it.
        let exact = meta.is_file().then_some(meta.len());
        self.install_from(&mut f, exact, downgrade, o, progress)
    }

    /// [`Platform::install`] from a stream (G1.6e: a package arriving over
    /// the control channel goes straight to the slot, never whole in RAM).
    /// `exact`: the package's size when the source knows it (a file, an
    /// upload's declared size); the manifest must say the same. The header
    /// and its signature are checked before a byte is written.
    pub fn install_from<R: Read + Send>(
        &self,
        f: &mut R,
        exact: Option<u64>,
        downgrade: bool,
        o: &Opts,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<Report, String> {
        let t0 = Instant::now();
        self.check_no_trial()?;
        let running = self.running().ok_or("cannot tell which slot is running")?;
        let target = running.other();
        let h = Header::read(f)?;
        h.verify(&self.keys)?;
        let m = &h.manifest;
        let total = h.len() + m.kernel.size + m.rootfs.size;
        if let Some(len) = exact
            && len != total
        {
            return Err(format!("package is {len} bytes, its manifest says {total}"));
        }
        self.version_policy(running, m, downgrade)?;
        let swap = if downgrade {
            self.downgrade_config(target, m, o)?
        } else {
            None
        };
        // G1.6u: the snapshot is the last step; a /config without room
        // for it is refused before the slot is touched.
        state::check_space(&self.config)?;
        let dev = self.dev(target)?.clone();
        if m.rootfs.size > dev.size {
            return Err(format!(
                "rootfs of {} bytes does not fit slot {} ({} bytes)",
                m.rootfs.size,
                target.as_str(),
                dev.size
            ));
        }
        self.detach(target)?;
        let esp_kernel = self.esp_dir.join(target.kernel_file());
        let esp_header = self.esp_dir.join(target.header_file());
        let mut rep = Report {
            slot: Some(target),
            version: m.version.clone(),
            bytes: m.kernel.size + m.rootfs.size,
            copied: true,
            ..Report::default()
        };
        let all = rep.bytes;
        self.esp_rw(|| {
            match std::fs::remove_file(&esp_header) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                    return Err(format!("{}: {e}", esp_header.display()));
                }
                _ => {}
            }
            if let Some(p) = esp_kernel.parent() {
                std::fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
            }
            let mut k =
                File::create(&esp_kernel).map_err(|e| format!("{}: {e}", esp_kernel.display()))?;
            let mut d = open_slot(&dev.path)?;
            let tw = Instant::now();
            let mut parts: [(u64, &mut dyn Write); 2] =
                [(m.kernel.size, &mut k), (m.rootfs.size, &mut d)];
            let c = package::copy(f, &mut parts, o.pipelined, &mut |n| progress(n, all))?;
            if c.sha256.first() != Some(&m.kernel.sha256)
                || c.sha256.get(1) != Some(&m.rootfs.sha256)
            {
                return Err(
                    "payload does not match its signed hashes: nothing was activated".into(),
                );
            }
            k.sync_all().map_err(|e| format!("kernel: {e}"))?;
            d.sync_all().map_err(|e| format!("slot: {e}"))?;
            rep.write_ms = tw.elapsed().as_millis() as u64;
            Ok(())
        })?;
        let tv = Instant::now();
        self.check_slot(target, m, o.threads)?;
        rep.verify_ms = tv.elapsed().as_millis() as u64;
        self.esp_rw(|| state::write_atomic(&esp_header, &h.bytes))?;
        let (cmdline, snap_ms) = self.arm_trial(running, target, m, o, swap)?;
        rep.cmdline = cmdline;
        rep.snapshot_ms = snap_ms;
        rep.total_ms = t0.elapsed().as_millis() as u64;
        self.record(&rep)?;
        Ok(rep)
    }

    /// Keeps the install's numbers with the trial (read after the reboot).
    fn record(&self, rep: &Report) -> Result<(), String> {
        let dir = self.state_dir();
        let (mut st, _) = State::load(&dir);
        if let Some(t) = st.trial.as_mut() {
            t.stats = Some(rep.json());
        }
        st.save(&dir)
    }

    fn version_policy(&self, running: SlotId, m: &Manifest, downgrade: bool) -> Result<(), String> {
        let Some((cur, _)) = self.header(running) else {
            return Ok(()); // a development image without a header: anything goes
        };
        let c = &cur.manifest;
        if downgrade && m.build >= c.build {
            return Err(format!(
                "{} is not older than the running {}: use system.package.update",
                m.version, c.version
            ));
        }
        if !downgrade && m.build < c.build {
            return Err(format!(
                "{} is older than the running {}: use system.package.downgrade",
                m.version, c.version
            ));
        }
        Ok(())
    }

    /// The configuration a downgrade to `target` boots with: the snapshot
    /// taken when `target` was left, when it is one the older image reads;
    /// otherwise the current one if its format is not newer than what the
    /// older image reads.
    fn downgrade_config(
        &self,
        target: SlotId,
        m: &Manifest,
        o: &Opts,
    ) -> Result<Option<String>, String> {
        let (name, _) = state::snapshot_dir(&self.config, target);
        if let Some(meta) = state::snapshot_meta(&self.config, &name)
            && meta
                .format_version
                .is_none_or(|f| f <= u64::from(m.config_format))
        {
            return Ok(Some(name));
        }
        if o.config_format <= m.config_format {
            return Ok(None);
        }
        Err(format!(
            "{} reads configuration format {} and the running one is {}, with no snapshot of slot {} to go back to",
            m.version,
            m.config_format,
            o.config_format,
            target.as_str()
        ))
    }

    /// Reads the slot back (bypassing the page cache) and recomputes its
    /// verity tree: the root must be the signed one and the tree on disk
    /// the computed one.
    pub fn check_slot(&self, s: SlotId, m: &Manifest, threads: usize) -> Result<u64, String> {
        let t = Instant::now();
        let dev = self.dev(s)?;
        let mut f = File::open(&dev.path).map_err(|e| format!("{}: {e}", dev.path.display()))?;
        drop_cache(&f);
        let mut data = vec![0u8; m.rootfs.size as usize];
        f.read_exact(&mut data)
            .map_err(|e| format!("read back slot {}: {e}", s.as_str()))?;
        let split = (m.rootfs.data_blocks as usize) * verity::BLOCK;
        let (d, on_disk) = data.split_at(split.min(data.len()));
        let salt = verity::unhex(&m.rootfs.salt).ok_or("salt")?;
        let tree = verity::tree(d, &salt, threads)?;
        if verity::hex(&tree.root) != m.rootfs.root_hash || tree.bytes != on_disk {
            return Err(format!(
                "slot {}: what was read back does not match the signed root hash",
                s.as_str()
            ));
        }
        Ok(t.elapsed().as_millis() as u64)
    }

    /// Scrub: is slot `s` still exactly its signed image?
    pub fn scrub(&self, s: SlotId, threads: usize) -> Result<Value, String> {
        let h = self.verified_header(s)?;
        let ms = self.check_slot(s, &h.manifest, threads)?;
        Ok(json!({"slot": s.as_str(), "ok": true, "millis": ms, "bytes": h.manifest.rootfs.size}))
    }

    /// Boot entry, configuration snapshot, trial state, `BootNext`.
    fn arm_trial(
        &self,
        from: SlotId,
        target: SlotId,
        m: &Manifest,
        o: &Opts,
        swap: Option<String>,
    ) -> Result<(String, u64), String> {
        let n = self.write_entry(target, m, &o.tuning, o.drill)?;
        let ts = Instant::now();
        let from_version = self
            .header(from)
            .map(|(h, _)| h.manifest.version)
            .unwrap_or_else(|| "unknown".into());
        let (backup, _) = state::snapshot(&self.config, from, &from_version, o.now)?;
        let snap_ms = ts.elapsed().as_millis() as u64;
        let (mut st, _) = State::load(&self.state_dir());
        st.failed.remove(&target);
        st.trial = Some(Trial {
            slot: target,
            from,
            version: m.version.clone(),
            reason: o.reason.clone(),
            confirm: o.confirm,
            timeout_s: o.timeout_s,
            started_unix: o.now,
            booted: false,
            mgmt: o.mgmt.clone(),
            config_swap: swap,
            config_backup: Some(backup),
            stats: None,
        });
        st.save(&self.state_dir())?;
        self.vars
            .set_u16_list("BootNext", &[n])
            .map_err(|e| format!("BootNext: {e}"))?;
        let cmdline = self
            .vars
            .load_option(n)
            .map(|o| o.cmdline)
            .unwrap_or_default();
        Ok((cmdline, snap_ms))
    }

    /// Tuning › Boot (G1.26h): the running image copied to the inactive
    /// slot (skipped when it already holds the same image) with a new
    /// command line, and its trial boot. The running slot is not touched.
    pub fn clone_running(
        &self,
        o: &Opts,
        progress: &mut dyn FnMut(u64, u64),
    ) -> Result<Report, String> {
        let t0 = Instant::now();
        self.check_no_trial()?;
        let running = self.running().ok_or("cannot tell which slot is running")?;
        let target = running.other();
        let h = self.verified_header(running).map_err(|e| {
            format!("{e} (booted by the fallback path? install a package once first)")
        })?;
        let m = &h.manifest;
        let mut rep = Report {
            slot: Some(target),
            version: m.version.clone(),
            ..Report::default()
        };
        let same = self
            .header(target)
            .is_some_and(|(t, v)| v.is_ok() && t.bytes == h.bytes);
        state::check_space(&self.config)?;
        if !same {
            let dev_from = self.dev(running)?.clone();
            let dev_to = self.dev(target)?.clone();
            if m.rootfs.size > dev_to.size {
                return Err("the running image does not fit the other slot".into());
            }
            self.detach(target)?;
            let k_from = self.esp_dir.join(running.kernel_file());
            let k_to = self.esp_dir.join(target.kernel_file());
            let hdr_to = self.esp_dir.join(target.header_file());
            rep.bytes = m.kernel.size + m.rootfs.size;
            let all = rep.bytes;
            self.esp_rw(|| {
                let _ = std::fs::remove_file(&hdr_to);
                if let Some(p) = k_to.parent() {
                    std::fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
                }
                let tw = Instant::now();
                let mut src = File::open(&k_from)
                    .map_err(|e| format!("{}: {e}", k_from.display()))?
                    .chain(
                        File::open(&dev_from.path)
                            .map_err(|e| format!("{}: {e}", dev_from.path.display()))?,
                    );
                let mut k = File::create(&k_to).map_err(|e| format!("{}: {e}", k_to.display()))?;
                let mut d = open_slot(&dev_to.path)?;
                let mut parts: [(u64, &mut dyn Write); 2] =
                    [(m.kernel.size, &mut k), (m.rootfs.size, &mut d)];
                let c =
                    package::copy(&mut src, &mut parts, o.pipelined, &mut |n| progress(n, all))?;
                if c.sha256.first() != Some(&m.kernel.sha256)
                    || c.sha256.get(1) != Some(&m.rootfs.sha256)
                {
                    return Err(
                        "the running image does not match its signed hashes: not copied".into(),
                    );
                }
                k.sync_all().map_err(|e| format!("kernel: {e}"))?;
                d.sync_all().map_err(|e| format!("slot: {e}"))?;
                rep.write_ms = tw.elapsed().as_millis() as u64;
                rep.copied = true;
                Ok(())
            })?;
            let tv = Instant::now();
            self.check_slot(target, m, o.threads)?;
            rep.verify_ms = tv.elapsed().as_millis() as u64;
            self.esp_rw(|| state::write_atomic(&hdr_to, &h.bytes))?;
        }
        let (cmdline, snap_ms) = self.arm_trial(running, target, m, o, None)?;
        rep.cmdline = cmdline;
        rep.snapshot_ms = snap_ms;
        rep.total_ms = t0.elapsed().as_millis() as u64;
        self.record(&rep)?;
        Ok(rep)
    }

    /// `system.package.downgrade` without a package: the trial boot of the
    /// other slot, which must hold an older signed image.
    pub fn switch_back(&self, o: &Opts) -> Result<Report, String> {
        let t0 = Instant::now();
        self.check_no_trial()?;
        let running = self.running().ok_or("cannot tell which slot is running")?;
        let target = running.other();
        let h = self.verified_header(target)?;
        self.version_policy(running, &h.manifest, true)?;
        let swap = self.downgrade_config(target, &h.manifest, o)?;
        let (cmdline, snap_ms) = self.arm_trial(running, target, &h.manifest, o, swap)?;
        Ok(Report {
            slot: Some(target),
            version: h.manifest.version.clone(),
            cmdline,
            snapshot_ms: snap_ms,
            total_ms: t0.elapsed().as_millis() as u64,
            ..Report::default()
        })
    }

    /// Confirms the trial running now: `BootOrder` starts with it.
    pub fn confirm(&self, now: u64, detail: &str) -> Result<Outcome, String> {
        let dir = self.state_dir();
        let (mut st, err) = State::load(&dir);
        if let Some(e) = err {
            return Err(e);
        }
        let t = st.trial.clone().ok_or("no trial boot to confirm")?;
        if self.running() != Some(t.slot) {
            return Err(format!(
                "the trial slot {} is not the one running",
                t.slot.as_str()
            ));
        }
        let ents = entries(&self.vars);
        self.set_order(t.slot, &ents)?;
        let out = Outcome {
            result: "confirmed".into(),
            slot: t.slot,
            version: t.version.clone(),
            at_unix: now,
            detail: detail.to_owned(),
            stats: t.stats.clone(),
        };
        st.trial = None;
        st.failed.remove(&t.slot);
        st.last = Some(out.clone());
        st.save(&dir)?;
        Ok(out)
    }

    /// Abandons an armed trial before its reboot (the next boot stays on
    /// the running slot).
    pub fn cancel(&self) -> Result<(), String> {
        let dir = self.state_dir();
        let (mut st, _) = State::load(&dir);
        let Some(t) = st.trial.clone() else {
            return Err("no trial to cancel".into());
        };
        if self.running() == Some(t.slot) {
            return Err("the trial is running: it can only be confirmed or let roll back".into());
        }
        let _ = self.vars.remove("BootNext");
        st.trial = None;
        st.save(&dir)
    }

    /// Virtual lab: what the firmware and the kernel do on a reboot —
    /// `BootNext` (consumed) or the first of `BootOrder` decides the slot,
    /// the command line becomes the built-in one plus the entry's options,
    /// then init's boot step runs. A drill (or a missing slot image) is a
    /// boot that fails: the firmware falls through to the next entry.
    pub fn lab_reboot(&mut self) -> Result<(Boot, Vec<String>), String> {
        let lab = self.lab.clone().ok_or("not a lab platform")?;
        let mut log = Vec::new();
        let ents = entries(&self.vars);
        let mut candidates: Vec<u16> = Vec::new();
        if let Some(n) = self.vars.boot_next() {
            candidates.push(n);
            let _ = self.vars.remove("BootNext");
        }
        candidates.extend(self.vars.boot_order().unwrap_or_default());
        let mut booted = None;
        for n in candidates {
            let Some(s) = SlotId::ALL
                .into_iter()
                .find(|s| ents.get(idx(*s)).copied().flatten() == Some(n))
            else {
                continue;
            };
            let opt = self
                .vars
                .load_option(n)
                .map(|o| o.cmdline)
                .unwrap_or_default();
            let ok =
                self.header(s).is_some_and(|(_, v)| v.is_ok()) && !opt.contains(crate::DRILL_INIT);
            if ok {
                booted = Some((n, s, opt));
                break;
            }
            log.push(format!(
                "lab: slot {} did not boot (panic=10: reboot)",
                s.as_str()
            ));
            // The failed boot resets: only BootOrder from now on.
        }
        let (n, s, opt) = booted.ok_or("lab: no slot boots")?;
        self.cmdline = format!("{} {opt}", crate::BUILTIN_CMDLINE);
        std::fs::write(lab.join("cmdline"), &self.cmdline).map_err(|e| e.to_string())?;
        self.vars
            .set_u16_list("BootCurrent", &[n])
            .map_err(|e| e.to_string())?;
        log.push(format!("lab: booted slot {}", s.as_str()));
        let (b, more) = at_boot(&self.config, &self.vars, &self.cmdline, self.partuuids());
        log.extend(more);
        Ok((b, log))
    }

    /// Virtual lab: a new lab's slot A gets a small synthetic image, signed
    /// by a key of the lab itself (`lab-key.pk8`, trusted by this lab only),
    /// as the factory image would be, and its boot entry. Nothing when slot
    /// A already holds one.
    pub fn lab_seed(&mut self, version: &str, build: u64) -> Result<bool, String> {
        let lab = self.lab.clone().ok_or("not a lab platform")?;
        let key_path = lab.join("lab-key.pk8");
        let key = match std::fs::read(&key_path) {
            Ok(k) => k,
            Err(_) => {
                let k = package::generate_key()?;
                state::write_atomic(&key_path, &k)?;
                k
            }
        };
        let public = Key::from_hex(&package::public_hex(&key)?).ok_or("lab key")?;
        if !self.keys.contains(&public) {
            self.keys.push(public);
        }
        if self.header(SlotId::A).is_some() {
            return Ok(false);
        }
        let kernel: Vec<u8> = (0..65536u32).map(|i| (i % 241) as u8).collect();
        let data: Vec<u8> = (0..64 * verity::BLOCK as u32)
            .map(|i| (i % 239) as u8)
            .collect();
        let salt = [0x5a, 0x17];
        let tree = verity::tree(&data, &salt, 1)?;
        let mut rootfs = data;
        rootfs.extend_from_slice(&tree.bytes);
        let m = Manifest {
            format: 1,
            version: version.into(),
            build,
            commit: "lab".into(),
            channel: "stable".into(),
            kernel_version: "virtual".into(),
            config_format: 1,
            kernel: package::Blob {
                size: kernel.len() as u64,
                sha256: package::sha256_hex(&kernel),
            },
            rootfs: package::Rootfs {
                size: rootfs.len() as u64,
                sha256: package::sha256_hex(&rootfs),
                data_blocks: tree.data_blocks,
                hash_blocks: tree.hash_blocks,
                salt: verity::hex(&salt),
                root_hash: verity::hex(&tree.root),
            },
        };
        let hdr = package::sign(&m, &key)?;
        let dev = self.dev(SlotId::A)?.clone();
        let mut d = open_slot(&dev.path)?;
        d.write_all(&rootfs).map_err(|e| e.to_string())?;
        let k = self.esp_dir.join(SlotId::A.kernel_file());
        if let Some(parent) = k.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(&k, &kernel).map_err(|e| e.to_string())?;
        state::write_atomic(&self.esp_dir.join(SlotId::A.header_file()), &hdr)?;
        // Booted through the fallback path, then provisioned: the factory flow.
        self.cmdline = crate::BUILTIN_CMDLINE.to_owned();
        self.provision(&[])?;
        Ok(true)
    }

    /// A directory that stands in for the router (virtual lab, tests):
    /// `efivars/`, `esp/`, `rootfs-a`, `rootfs-b` (sparse files) and
    /// `cmdline`. A new lab boots slot A with no image in it.
    pub fn lab(
        dir: &Path,
        config: &Path,
        keys: Vec<Key>,
        slot_size: u64,
    ) -> Result<Platform, String> {
        let e = |p: &Path, err: std::io::Error| format!("{}: {err}", p.display());
        for d in ["efivars", "esp"] {
            std::fs::create_dir_all(dir.join(d)).map_err(|err| e(&dir.join(d), err))?;
        }
        let mut slots = Vec::new();
        for (s, uuid) in [
            (SlotId::A, "3e1088b8-5b4b-4fbb-b756-a271f641d018"),
            (SlotId::B, "868e1d1d-85bb-4c62-a083-f61aa7a5cda2"),
        ] {
            let path = dir.join(s.partition());
            let f = std::fs::OpenOptions::new()
                .create(true)
                .truncate(false)
                .write(true)
                .open(&path)
                .map_err(|err| e(&path, err))?;
            if f.metadata().map(|m| m.len()).unwrap_or(0) < slot_size {
                f.set_len(slot_size).map_err(|err| e(&path, err))?;
            }
            slots.push(SlotDev {
                path,
                partuuid: uuid.into(),
                size: slot_size,
            });
        }
        let cmdline_path = dir.join("cmdline");
        let cmdline = std::fs::read_to_string(&cmdline_path)
            .unwrap_or_else(|_| crate::BUILTIN_CMDLINE.to_owned());
        let [a, b]: [SlotDev; 2] = slots.try_into().map_err(|_| "slots".to_string())?;
        Ok(Platform {
            vars: Vars::directory(dir.join("efivars")),
            esp_dir: dir.join("esp"),
            esp_remount: false,
            esp: Partition {
                number: 1,
                start_lba: 2048,
                size_lba: 262144,
                guid: "4f9a520b-35f7-4633-a4bb-e9f871d1473c".into(),
            },
            slots: [a, b],
            keys,
            config: config.to_owned(),
            cmdline,
            lab: Some(dir.to_owned()),
        })
    }
}

fn open_slot(path: &Path) -> Result<File, String> {
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    Ok(f)
}

/// Drops `f`'s pages from the page cache, so a read-back comes from the
/// disk and not from what was just written.
pub(crate) fn drop_cache(f: &File) {
    #[cfg(target_os = "linux")]
    {
        let _ = rustix::fs::fadvise(f, 0, None, rustix::fs::Advice::DontNeed);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = f;
}

/// Linux: the platform of the running CoreRouter image, or why there is
/// none. Refuses anything but the image (PID 1 must be `corerouter-init`):
/// on a development machine the daemon must never write the host's boot
/// variables nor its disks.
#[cfg(target_os = "linux")]
pub fn discover(config: &Path, keys_dir: &Path, esp_mount: &Path) -> Result<Platform, String> {
    let comm = std::fs::read_to_string("/proc/1/comm").unwrap_or_default();
    if comm.trim() != "corerouter-init" {
        return Err(
            "not the CoreRouter image (PID 1 is not corerouter-init): A/B updates are off".into(),
        );
    }
    let efivars = Path::new("/sys/firmware/efi/efivars");
    if !crate::efi::available(efivars) {
        return Err(
            "not booted by UEFI (no efivarfs): A/B updates need the UEFI boot manager".into(),
        );
    }
    // Partitions by name, and the disk that holds them.
    let mut named: Vec<(String, String, String)> = Vec::new(); // (name, dev, disk)
    for e in std::fs::read_dir("/sys/class/block")
        .map_err(|e| e.to_string())?
        .flatten()
    {
        let dev = e.file_name().to_string_lossy().into_owned();
        let uevent = std::fs::read_to_string(e.path().join("uevent")).unwrap_or_default();
        let Some(name) = uevent.lines().find_map(|l| l.strip_prefix("PARTNAME=")) else {
            continue;
        };
        let disk = std::fs::canonicalize(e.path())
            .ok()
            .and_then(|p| p.parent()?.file_name()?.to_str().map(str::to_owned))
            .unwrap_or_default();
        named.push((name.to_owned(), dev, disk));
    }
    let find = |n: &str| named.iter().find(|(name, _, _)| name == n).cloned();
    let (_, _, disk) = find("rootfs-a").ok_or("no partition named rootfs-a")?;
    let lbs: u64 = std::fs::read_to_string(format!("/sys/block/{disk}/queue/logical_block_size"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(512);
    let mut f = File::open(format!("/dev/{disk}")).map_err(|e| format!("/dev/{disk}: {e}"))?;
    let gpt = crate::gpt::read(&mut f, lbs)?;
    let part = |n: &str| {
        gpt.iter()
            .find(|p| p.name == n)
            .cloned()
            .ok_or_else(|| format!("no partition named {n} on {disk}"))
    };
    let slot = |s: SlotId| -> Result<SlotDev, String> {
        let p = part(s.partition())?;
        let (_, dev, _) = find(s.partition()).ok_or("partition device")?;
        Ok(SlotDev {
            path: PathBuf::from(format!("/dev/{dev}")),
            partuuid: p.guid.clone(),
            size: p.size_lba() * lbs,
        })
    };
    let esp = part("efi")?;
    let (_, esp_dev, _) = find("efi").ok_or("ESP device")?;
    let mounted = std::fs::read_to_string("/proc/mounts")
        .unwrap_or_default()
        .lines()
        .any(|l| l.split_whitespace().nth(1) == esp_mount.to_str());
    if !mounted {
        use rustix::mount::{MountFlags, mount};
        std::fs::create_dir_all(esp_mount).map_err(|e| e.to_string())?;
        mount(
            format!("/dev/{esp_dev}").as_str(),
            esp_mount,
            "vfat",
            MountFlags::RDONLY | MountFlags::NOEXEC | MountFlags::NOSUID | MountFlags::NODEV,
            c"",
        )
        .map_err(|e| format!("mount ESP /dev/{esp_dev}: {e}"))?;
    }
    Ok(Platform {
        vars: Vars::efivarfs(efivars),
        esp_dir: esp_mount.to_owned(),
        esp_remount: true,
        esp: Partition {
            number: esp.number,
            start_lba: esp.first_lba,
            size_lba: esp.size_lba(),
            guid: esp.guid.clone(),
        },
        slots: [slot(SlotId::A)?, slot(SlotId::B)?],
        keys: package::load_keys(keys_dir),
        config: config.to_owned(),
        cmdline: std::fs::read_to_string("/proc/cmdline")
            .unwrap_or_default()
            .trim()
            .to_owned(),
        lab: None,
    })
}

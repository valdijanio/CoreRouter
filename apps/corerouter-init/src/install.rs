//! The installer (G1.6c, `docs/os-image.md`): what PID 1 does when the
//! installer ISO's kernel booted it (`corerouter.mode=install`, running
//! from the initramfs; the medium can be a CD or a USB stick).
//!
//! It finds the medium (the ISO's volume id, then the signed index), lists
//! the disks with size, model and bus, and installs only after the person
//! at a console typed the disk's name; the medium itself is never offered.
//! The writing and checking is `corerouter_sysupdate::install`; this file
//! adds the consoles, the disks and the UEFI boot entry.
//!
//! Unattended install: only from the hypervisor, through QEMU's fw_cfg
//! (`-fw_cfg name=opt/org.corerouter/autoinstall,string=<json>`), which no
//! physical machine has; it must name the disk twice (`disk`, `confirm`).
//! This is the test's flag (`cargo xtask os install-test`).

use std::fs::{File, OpenOptions};
use std::io::Seek;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

use corerouter_sysupdate::efi::{LoadOption, Vars, boot_name};
use corerouter_sysupdate::install::{self, Existing, Medium};
use corerouter_sysupdate::package;
use corerouter_sysupdate::{CARRY_PREFIXES, SlotCmdline, SlotId, ab};
use rustix::system::RebootCommand;

use crate::console::{self, Console};
use crate::plan::{self, BootOptions, Mgmt};

const KEYS: &str = "/etc/corerouter/image-keys";
const AUTOINSTALL: &str = "/sys/firmware/qemu_fw_cfg/by_name/opt/org.corerouter/autoinstall/raw";
/// USB sticks take a few seconds to show up.
const MEDIUM_WAIT: Duration = Duration::from_secs(30);

/// A disk that could be the target.
struct Disk {
    name: String,
    bytes: u64,
    lbs: u64,
    model: String,
    serial: String,
    bus: &'static str,
    removable: bool,
    existing: Existing,
    /// Why it cannot be the target.
    refused: Option<String>,
}

/// The unattended install asked by the hypervisor.
#[derive(Debug, PartialEq)]
struct Auto {
    disk: String,
    keep_config: bool,
    append: Vec<String>,
    mgmt: Option<Mgmt>,
    poweroff: bool,
}

fn parse_auto(text: &str) -> Result<Auto, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("not JSON: {e}"))?;
    let s = |k: &str| v.get(k).and_then(serde_json::Value::as_str);
    let disk = s("disk").ok_or("no \"disk\"")?;
    if s("confirm") != Some(disk) {
        return Err("\"confirm\" must repeat the disk name".into());
    }
    let mut append = Vec::new();
    for w in s("append").unwrap_or("").split_whitespace() {
        let ok =
            w.len() <= 64 && !w.contains('"') && CARRY_PREFIXES.iter().any(|p| w.starts_with(p));
        if !ok {
            return Err(format!(
                "\"append\": '{}' (only {})",
                w.chars().take(32).collect::<String>(),
                CARRY_PREFIXES.join(" ")
            ));
        }
        append.push(w.to_owned());
    }
    let mgmt = s("mgmt").map(Mgmt::parse).transpose()?;
    let poweroff = match s("then").unwrap_or("reboot") {
        "poweroff" => true,
        "reboot" => false,
        other => {
            return Err(format!(
                "\"then\": '{}' (poweroff or reboot)",
                other.chars().take(16).collect::<String>()
            ));
        }
    };
    Ok(Auto {
        disk: disk.to_owned(),
        keep_config: v
            .get("keep_config")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false),
        append,
        mgmt,
        poweroff,
    })
}

fn sys(path: &str) -> String {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

fn human(bytes: u64) -> String {
    let g = bytes as f64 / (1u64 << 30) as f64;
    if g >= 1.0 {
        format!("{g:.1} GiB")
    } else {
        format!("{} MiB", bytes >> 20)
    }
}

/// Whole disks (no partitions, loop, ram, device-mapper); optical drives
/// only with `optical` (the medium may be a CD, a target never is).
fn block_devices(optical: bool) -> Vec<String> {
    let mut out: Vec<String> = std::fs::read_dir("/sys/block")
        .map(|d| {
            d.flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| optical || !n.starts_with("sr"))
                .filter(|n| {
                    !["loop", "ram", "zram", "dm-", "md", "nbd", "fd"]
                        .iter()
                        .any(|p| n.starts_with(p))
                })
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

fn find_medium(con: &Console, keys: &[package::Key]) -> Result<(String, Medium<File>), String> {
    let t = Instant::now();
    let mut said = std::collections::BTreeSet::new();
    loop {
        for name in block_devices(true) {
            let Ok(mut f) = File::open(format!("/dev/{name}")) else {
                continue;
            };
            if !corerouter_sysupdate::iso::is_installer(&mut f) {
                continue;
            }
            match Medium::open(f, keys) {
                Ok(m) => return Ok((name, m)),
                Err(e) => {
                    if said.insert(name.clone()) {
                        con.say(&format!("  {name}: an installer medium, but unusable: {e}"));
                    }
                }
            }
        }
        if t.elapsed() >= MEDIUM_WAIT {
            return Err(format!(
                "no CoreRouter installer medium found in {} s (a damaged copy, or a stick that did not show up?)",
                MEDIUM_WAIT.as_secs()
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

fn bus(name: &str) -> &'static str {
    let p = std::fs::canonicalize(format!("/sys/block/{name}"))
        .map(|p| p.display().to_string())
        .unwrap_or_default();
    if p.contains("/usb") {
        "USB"
    } else if name.starts_with("nvme") {
        "NVMe"
    } else if p.contains("/virtio") {
        "virtio"
    } else if p.contains("/ata") {
        "SATA"
    } else if name.starts_with("mmcblk") {
        "SD/eMMC"
    } else if name.starts_with("sr") {
        "optical"
    } else {
        "SCSI"
    }
}

fn disks(medium: &str, index: &install::Index) -> Vec<Disk> {
    block_devices(false)
        .into_iter()
        .map(|name| {
            let base = format!("/sys/block/{name}");
            let bytes = sys(&format!("{base}/size")).parse::<u64>().unwrap_or(0) * 512;
            let lbs = sys(&format!("{base}/queue/logical_block_size"))
                .parse()
                .unwrap_or(512);
            let model = [
                sys(&format!("{base}/device/vendor")),
                sys(&format!("{base}/device/model")),
            ]
            .iter()
            // virtio's "vendor" is the PCI id (0x1af4), not a name.
            .filter(|s| !s.is_empty() && !s.starts_with("0x"))
            .cloned()
            .collect::<Vec<_>>()
            .join(" ");
            let serial = [format!("{base}/device/serial"), format!("{base}/serial")]
                .iter()
                .map(|p| sys(p))
                .find(|s| !s.is_empty())
                .unwrap_or_default();
            let mut existing = Existing::Unknown;
            let mut refused = None;
            if name == medium {
                refused = Some("the installer medium".into());
            } else if name.starts_with("sr") {
                refused = Some("optical drive".into());
            } else if sys(&format!("{base}/ro")) == "1" {
                refused = Some("read-only".into());
            } else if bytes < index.min_disk() {
                refused = Some(format!(
                    "smaller than the {} the image needs",
                    human(index.min_disk())
                ));
            }
            if let Ok(mut f) = File::open(format!("/dev/{name}")) {
                if corerouter_sysupdate::iso::is_installer(&mut f) {
                    refused.get_or_insert_with(|| "holds an installer image".into());
                }
                existing = install::existing(&mut f, lbs, index);
            } else {
                refused.get_or_insert_with(|| "cannot be opened".into());
            }
            Disk {
                bus: bus(&name),
                removable: sys(&format!("{base}/removable")) == "1",
                name,
                bytes,
                lbs,
                model,
                serial,
                existing,
                refused,
            }
        })
        .collect()
}

fn describe(e: &Existing) -> String {
    match e {
        Existing::Empty => "empty".into(),
        Existing::Gpt(names) if names.is_empty() => "GPT, no partitions".into(),
        Existing::Gpt(names) => format!("GPT: {}", names.join(", ")),
        Existing::CoreRouter { .. } => "CoreRouter".into(),
        Existing::Unknown => "data (MBR or a filesystem)".into(),
    }
}

/// The disks that can be the target, in the order they are numbered.
fn offered(ds: &[Disk]) -> Vec<&Disk> {
    ds.iter().filter(|d| d.refused.is_none()).collect()
}

fn table(con: &Console, ds: &[Disk]) {
    con.say("");
    con.say(&format!(
        "  {:<4}{:<10}{:<11}{:<32}{:<9}{}",
        "#", "name", "size", "model", "bus", "holds"
    ));
    for d in ds {
        let num = match offered(ds).iter().position(|o| o.name == d.name) {
            Some(n) if d.refused.is_none() => format!("{}", n + 1),
            _ => " ".into(),
        };
        let holds = match &d.refused {
            Some(r) => format!("{} — not offered: {r}", describe(&d.existing)),
            None => describe(&d.existing),
        };
        let model: String = if d.model.is_empty() {
            "-".into()
        } else {
            d.model.chars().take(30).collect()
        };
        let bus = if d.removable && d.bus != "USB" {
            format!("{} rem.", d.bus)
        } else {
            d.bus.to_owned()
        };
        con.say(&format!(
            "  {num:<4}{:<10}{:<11}{model:<32}{bus:<9}{holds}",
            d.name,
            human(d.bytes)
        ));
    }
    con.say("");
}

fn finish(con: &Console, poweroff: bool) -> ! {
    rustix::fs::sync();
    con.say(if poweroff {
        "Powering off."
    } else {
        "Rebooting."
    });
    let _ = rustix::system::reboot(if poweroff {
        RebootCommand::PowerOff
    } else {
        RebootCommand::Restart
    });
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}

/// PID 1 of the installer.
pub fn run(opts: &BootOptions, cmdline: &str) -> ! {
    let con = Console::open(&console::active(None));
    let auto_text = std::fs::read(AUTOINSTALL)
        .ok()
        .map(|b| String::from_utf8_lossy(b.get(..4096).unwrap_or(&b)).into_owned());
    let auto = auto_text.as_deref().map(parse_auto);
    let unattended = auto.is_some();
    match flow(&con, opts, cmdline, auto) {
        Ok(poweroff) => finish(&con, poweroff),
        Err(e) => {
            con.say(&format!("\ninstall failed: {e}"));
            if unattended {
                finish(&con, true);
            }
            let _ = con.ask("Press Enter to reboot. ", None);
            finish(&con, false)
        }
    }
}

fn flow(
    con: &Console,
    opts: &BootOptions,
    cmdline: &str,
    auto: Option<Result<Auto, String>>,
) -> Result<bool, String> {
    let release = sys("/etc/os-release");
    let pretty = release
        .lines()
        .find_map(|l| l.strip_prefix("PRETTY_NAME="))
        .unwrap_or("CoreRouter")
        .trim_matches('"')
        .to_owned();
    con.say(&format!(
        "\n{pretty} — installer (consoles: {})",
        con.names().join(", ")
    ));
    for w in &opts.warnings {
        con.say(&format!("kernel command line: {w}"));
    }
    if !Path::new("/sys/firmware/efi").exists() {
        return Err(
            "not booted by UEFI: CoreRouter boots only through the UEFI boot manager".into(),
        );
    }
    let keys = package::load_keys(Path::new(KEYS));
    con.say("Looking for the installer medium…");
    let (medium_dev, mut medium) = find_medium(con, &keys)?;
    let m = medium.header.manifest.clone();
    con.say(&format!(
        "Medium: {medium_dev} — CoreRouter {} (commit {}, {} channel), signed by key {}",
        m.version, m.commit, m.channel, medium.key
    ));
    let auto = match auto {
        Some(Ok(a)) => {
            con.say(&format!(
                "\nUNATTENDED INSTALL asked by the hypervisor (fw_cfg opt/org.corerouter/autoinstall): disk {}",
                a.disk
            ));
            Some(a)
        }
        Some(Err(e)) => return Err(format!("unattended install (fw_cfg): {e}")),
        None => None,
    };
    loop {
        let ds = disks(&medium_dev, &medium.index);
        table(con, &ds);
        let pick = match &auto {
            Some(a) => ds
                .iter()
                .find(|d| d.name == a.disk)
                .ok_or_else(|| format!("no disk named {}", a.disk))?,
            None => {
                let Some(line) = con.ask(
                    "Disk to install on (number or name; r: rescan, p: power off): ",
                    None,
                ) else {
                    return Err("console closed".into());
                };
                match line.as_str() {
                    "" | "r" => continue,
                    "p" => return Ok(true),
                    l => {
                        let by_num = l
                            .parse::<usize>()
                            .ok()
                            .and_then(|n| offered(&ds).get(n.wrapping_sub(1)).copied());
                        match by_num.or_else(|| ds.iter().find(|d| d.name == l)) {
                            Some(d) => d,
                            None => {
                                con.say(&format!(
                                    "No disk '{}'.",
                                    l.chars().take(32).collect::<String>()
                                ));
                                continue;
                            }
                        }
                    }
                }
            }
        };
        if let Some(r) = &pick.refused {
            if auto.is_some() {
                return Err(format!("{} cannot be the target: {r}", pick.name));
            }
            con.say(&format!("{} cannot be the target: {r}.", pick.name));
            continue;
        }
        con.say(&format!("\nALL DATA ON {} WILL BE ERASED:", pick.name));
        con.say(&format!(
            "  {}  {} ({} bytes)  {}  serial {}  {}  holds: {}",
            pick.name,
            human(pick.bytes),
            pick.bytes,
            if pick.model.is_empty() {
                "-"
            } else {
                &pick.model
            },
            if pick.serial.is_empty() {
                "-"
            } else {
                &pick.serial
            },
            pick.bus,
            describe(&pick.existing)
        ));
        let keepable = pick.existing
            == Existing::CoreRouter {
                config_keepable: true,
            };
        let (keep, mgmt, append) = match &auto {
            Some(a) => (a.keep_config, a.mgmt.clone(), a.append.clone()),
            None => {
                let keep = keepable
                    && con
                        .ask(
                            "Keep the CoreRouter configuration that is on it? [y/N] ",
                            None,
                        )
                        .is_some_and(|l| l.eq_ignore_ascii_case("y"));
                // G1.6m: the names the router gives them on its first
                // boot (bus order), with link and MAC to find the cable.
                let ports: Vec<(String, String, bool)> = crate::links::ports_with_link()
                    .into_iter()
                    .map(|(f, up)| (f.kernel, f.mac, up))
                    .collect();
                let mgmt = loop {
                    con.say("Management address for the first boot: <port> <address/prefix> [<gateway>]");
                    for p in &ports {
                        con.say(&format!("  {}", crate::setup::describe(p)));
                    }
                    let Some(l) = con.ask("(e.g. ether1 192.0.2.10/24 192.0.2.1; empty: none, set it on the console later): ", None) else {
                        return Err("console closed".into());
                    };
                    if l.is_empty() {
                        break None;
                    }
                    match Mgmt::parse(&l.split_whitespace().collect::<Vec<_>>().join(",")) {
                        Ok(m) if !ports.is_empty() && !ports.iter().any(|p| p.0 == m.interface) => {
                            con.say(&format!("There is no port {} here.", m.interface));
                        }
                        Ok(m) => break Some(m),
                        Err(e) => con.say(&e),
                    }
                };
                let typed = con.ask(
                    &format!("Type the disk name ({}) to erase it and install, anything else goes back: ", pick.name),
                    None,
                );
                if typed.as_deref() != Some(pick.name.as_str()) {
                    con.say("Nothing was written.");
                    continue;
                }
                (keep, mgmt, Vec::new())
            }
        };
        let running = format!("{cmdline} {}", append.join(" "));
        let poweroff = auto.as_ref().is_some_and(|a| a.poweroff);
        let report = write(con, &mut medium, pick, keep)?;
        match boot_entry(&report, &m, &running, mgmt.as_ref()) {
            Ok(line) => con.say(&line),
            Err(e) => con.say(&format!(
                "boot entry: {e} — the firmware boots the disk by its removable-media path; the router makes its entries on the first boot"
            )),
        }
        con.say(&format!(
            "\nINSTALLED CoreRouter {} on {} in {:.1} s ({} MiB written in {} ms, read back in {} ms){}",
            m.version,
            pick.name,
            report.total_ms as f64 / 1000.0,
            report.bytes_written >> 20,
            report.write_ms,
            report.verify_ms,
            if report.kept_config { ", configuration kept" } else { "" }
        ));
        if auto.is_none() {
            let _ = con.ask(
                "Remove the installation medium and press Enter to reboot. ",
                None,
            );
        }
        return Ok(poweroff);
    }
}

fn write(
    con: &Console,
    medium: &mut Medium<File>,
    d: &Disk,
    keep: bool,
) -> Result<install::Report, String> {
    // O_EXCL on a block device: refused while anything (a mount, a holder)
    // uses it.
    let target = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(rustix::fs::OFlags::EXCL.bits() as i32)
        .open(format!("/dev/{}", d.name))
        .map_err(|e| format!("/dev/{}: {e}", d.name))?;
    let mut t = &target;
    let size = t
        .seek(std::io::SeekFrom::End(0))
        .map_err(|e| e.to_string())?;
    con.say(&format!("Writing {}…", d.name));
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let started = Instant::now();
    let mut shown = 0u64;
    let r = install::install(
        medium,
        &target,
        size,
        d.lbs,
        &install::Opts {
            keep_config: keep,
            pipelined: true,
            parallel_verify: true,
            threads,
        },
        &mut |done, total| {
            let pct = done * 100 / total.max(1);
            if pct >= shown + 10 || done == total {
                shown = pct;
                let s = started.elapsed().as_secs_f64().max(0.001);
                con.say(&format!(
                    "  {pct:>3}%  {} of {} MiB  {:.0} MiB/s",
                    done >> 20,
                    total >> 20,
                    done as f64 / 1048576.0 / s
                ));
            }
        },
    )?;
    con.say(&format!(
        "Verified: ESP and /config by SHA-256, slot A by its dm-verity tree; partition table written and read back (sync {} ms)",
        r.sync_ms
    ));
    Ok(r)
}

/// `Boot####` "CoreRouter A" for the new disk, first in `BootOrder`; an
/// earlier install's "CoreRouter B" entry goes (its slot is empty now).
fn boot_entry(
    r: &install::Report,
    m: &package::Manifest,
    running: &str,
    mgmt: Option<&Mgmt>,
) -> Result<String, String> {
    let vars = Vars::efivarfs(plan::EFIVARS.target);
    let ents = ab::entries(&vars);
    let tuning: Vec<(String, String)> = mgmt
        .map(|g| vec![("corerouter.mgmt".to_owned(), g.render())])
        .unwrap_or_default();
    let line = SlotCmdline {
        slot: SlotId::A,
        partuuid: &r.rootfs_a,
        manifest: m,
        tuning: &tuning,
        running,
        drill: false,
    }
    .render();
    let opt = LoadOption {
        active: true,
        description: SlotId::A.label().into(),
        partition: r.esp.clone(),
        file: Some(SlotId::A.efi_path()),
        cmdline: line,
    };
    let used = vars.boot_numbers();
    let n = match ents.first().copied().flatten() {
        Some(n) => n,
        None => (0..=0xffffu16)
            .find(|n| !used.contains(n))
            .ok_or("no free Boot#### number")?,
    };
    vars.set(&boot_name(n), &opt.encode()?)
        .map_err(|e| format!("{}: {e}", boot_name(n)))?;
    let stale_b = ents.get(1).copied().flatten();
    if let Some(b) = stale_b {
        let _ = vars.remove(&boot_name(b));
    }
    let mut order = vec![n];
    for x in vars.boot_order().unwrap_or_default() {
        if x != n && Some(x) != stale_b {
            order.push(x);
        }
    }
    vars.set_u16_list("BootOrder", &order)
        .map_err(|e| format!("BootOrder: {e}"))?;
    Ok(format!(
        "Boot entry {} \"{}\" first in BootOrder{}",
        boot_name(n),
        SlotId::A.label(),
        mgmt.map(|g| format!(
            "; management address {} on {} at the first boot",
            g.address, g.interface
        ))
        .unwrap_or_default()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unattended_requests_are_strict() {
        let a = parse_auto(r#"{"disk":"vda","confirm":"vda","append":"corerouter.shell=ttyS0","mgmt":"eth0,10.0.2.15/24,10.0.2.2","then":"poweroff"}"#).unwrap();
        assert_eq!(a.disk, "vda");
        assert!(a.poweroff && !a.keep_config);
        assert_eq!(a.append, ["corerouter.shell=ttyS0"]);
        assert_eq!(a.mgmt.unwrap().interface, "eth0");
        assert!(
            !parse_auto(r#"{"disk":"vda","confirm":"vda"}"#)
                .unwrap()
                .poweroff
        );
        for bad in [
            r#"{"disk":"vda"}"#,
            r#"{"disk":"vda","confirm":"vdb"}"#,
            r#"{"disk":"vda","confirm":"vda","append":"init=/bin/sh"}"#,
            r#"{"disk":"vda","confirm":"vda","append":"console=\"x"}"#,
            r#"{"disk":"vda","confirm":"vda","then":"explode"}"#,
            r#"{"disk":"vda","confirm":"vda","mgmt":"eth0"}"#,
            "not json",
        ] {
            assert!(parse_auto(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn sizes_read_well() {
        assert_eq!(human(8 << 30), "8.0 GiB");
        assert_eq!(human(700 << 20), "700 MiB");
        assert_eq!(
            describe(&Existing::Gpt(vec!["efi".into(), "root".into()])),
            "GPT: efi, root"
        );
    }
}

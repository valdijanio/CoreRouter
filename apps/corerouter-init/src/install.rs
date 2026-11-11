//! The installer (G1.6c, `docs/os-image.md`): what PID 1 does when the
//! installer ISO's kernel booted it and the console is what is left: the
//! live image could not start, `i` on its console, or the hypervisor asked
//! (`corerouter.mode=install` still means this directly). It runs from the
//! initramfs; the medium can be a CD or a USB stick.
//!
//! It finds the medium (the ISO's volume id, then the signed index), lists
//! the disks with size, model and bus, and installs only after the person
//! at a console typed the disk's name; the medium itself is never offered.
//! The writing and checking is `corerouter_sysupdate::install`; this file
//! adds the consoles, the disks and the UEFI boot entry (G1.6g: on a BIOS,
//! the disk already boots through GRUB, whose configuration the install
//! writes with the same command line).
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

use corerouter_sysupdate::CARRY_PREFIXES;
use corerouter_sysupdate::disks::{self, Disk, describe, human, sys};
use corerouter_sysupdate::install::{self, Existing, Medium};
use corerouter_sysupdate::package;
use rustix::system::RebootCommand;

use crate::console::{self, Console};
use crate::plan::{self, BootOptions, Mgmt};
use crate::style::{self, bad, dim, good, key, title, warn};

pub(crate) use corerouter_sysupdate::disks::KEYS;
pub(crate) const AUTOINSTALL: &str =
    "/sys/firmware/qemu_fw_cfg/by_name/opt/org.corerouter/autoinstall/raw";
/// USB sticks take a few seconds to show up.
const MEDIUM_WAIT: Duration = Duration::from_secs(30);

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

pub(crate) fn find_medium(
    con: &Console,
    keys: &[package::Key],
) -> Result<(String, Medium<File>), String> {
    let t = Instant::now();
    let mut said = std::collections::BTreeSet::new();
    loop {
        let found = disks::find_medium(keys, &mut |name, e| {
            if said.insert(name.to_owned()) {
                con.say(&style::block(
                    2,
                    &warn("WARNING"),
                    9,
                    &format!("{name}: an installer medium, but unusable: {e}"),
                ));
            }
        });
        if let Some(m) = found {
            return Ok(m);
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

/// The steps the installer walks through (G1.6zg).
const STEPS: usize = 5;

/// The disks that can be the target, in the order they are numbered.
fn offered(ds: &[Disk]) -> Vec<&Disk> {
    ds.iter().filter(|d| d.refused.is_none()).collect()
}

fn or_dash(s: &str) -> String {
    let s = style::ascii(s);
    if s.is_empty() { "-".to_owned() } else { s }
}

fn bus(d: &Disk) -> String {
    if d.removable && d.bus != "USB" {
        format!("{} rem.", d.bus)
    } else {
        d.bus.to_owned()
    }
}

/// The disks: the ones that can be the target numbered and bright, the
/// others dimmed, without a number and with the reason on a line of its own.
fn table(ds: &[Disk]) -> String {
    let row = |num: &str, name: &str, size: &str, model: &str, bus: &str, holds: &str| {
        format!(
            "{num:>3}  {name:<9}{size:<11}{:<23}{bus:<10}{}",
            style::clip(model, 22),
            style::clip(holds, 18)
        )
        .trim_end()
        .to_owned()
    };
    let mut out = format!(
        "  {}",
        title(&row("#", "NAME", "SIZE", "MODEL", "BUS", "HOLDS"))
    );
    let mut n = 0;
    for d in ds {
        let line = |num: &str| {
            row(
                num,
                &style::ascii(&d.name),
                &human(d.bytes),
                &or_dash(&d.model),
                &bus(d),
                &describe(&d.existing),
            )
        };
        match &d.refused {
            None => {
                n += 1;
                out.push_str(&format!("\n  {}", title(&line(&n.to_string()))));
            }
            Some(why) => {
                out.push_str(&format!("\n  {}", dim(&line("-"))));
                out.push_str(&format!(
                    "\n{}",
                    dim(&style::block(7, "", 0, &format!("not offered: {why}")))
                ));
            }
        }
    }
    if ds.is_empty() {
        out.push_str("\n  no disk found");
    }
    out
}

/// What is about to be erased, and what goes on it: the last screen before
/// the disk's name is typed.
fn confirm_text(d: &Disk, version: &str, keep: bool, mgmt: Option<&Mgmt>) -> String {
    let row = |label: &str, value: &str| style::block(2, label, 9, value);
    let holds = match (&d.existing, keep) {
        (Existing::CoreRouter { .. }, true) => {
            "CoreRouter: its configuration is kept, the rest is erased".to_owned()
        }
        (e, _) => describe(e),
    };
    [
        format!(
            "  {}",
            bad(&format!(
                "!! ALL DATA ON {} WILL BE ERASED !!",
                style::ascii(&d.name)
            ))
        ),
        row(
            "Disk",
            &format!(
                "{}, {} ({} bytes), {}",
                title(&style::ascii(&d.name)),
                human(d.bytes),
                d.bytes,
                bus(d)
            ),
        ),
        row("Model", &or_dash(&d.model)),
        row("Serial", &or_dash(&d.serial)),
        row("Holds", &holds),
        row("Install", &format!("CoreRouter {version}")),
        row(
            "Address",
            &match mgmt {
                Some(m) => format!("{} on {}{}", m.address, m.interface, gateway_note(m)),
                None if keep => "as in the configuration that is kept".to_owned(),
                None => "none: the console asks for it on the first boot".to_owned(),
            },
        ),
    ]
    .join("\n")
}

fn gateway_note(m: &Mgmt) -> String {
    m.gateway
        .as_ref()
        .map(|g| format!(", gateway {g}"))
        .unwrap_or_default()
}

/// What to do once the install is done, after the green line.
fn next_text(keep: bool, mgmt: Option<&Mgmt>, attended: bool) -> String {
    let mut out = Vec::new();
    if attended {
        out.push(format!(
            "  {} remove the installation medium, then press {} to reboot.",
            title("Next:"),
            key("Enter")
        ));
    }
    out.push(match mgmt {
        Some(m) => {
            let host = m.address.split('/').next().unwrap_or("");
            let host = if host.contains(':') {
                format!("[{host}]")
            } else {
                host.to_owned()
            };
            style::block(
                2,
                "",
                0,
                &format!(
                    "Then open {} (through {}; user admin{}).",
                    key(&format!("https://{host}/")),
                    m.interface,
                    if keep { "" } else { ", no password yet" }
                ),
            )
        }
        None if keep => "  The router comes up with the configuration that was kept.".to_owned(),
        None => "  On its first boot the console asks for the management address.".to_owned(),
    });
    out.join("\n")
}

fn finish(con: &Console, poweroff: bool) -> ! {
    rustix::fs::sync();
    con.say(if poweroff {
        "  Powering off."
    } else {
        "  Rebooting."
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

/// What a failed install says: the cause, and what to do next.
fn failure_text(e: &str) -> String {
    format!(
        "\n{}\n{}",
        style::block(2, &bad("FAILED"), 8, &format!("The install failed: {e}")),
        style::block(
            10,
            "",
            0,
            "If the writing had started, that disk does not boot until an install completes."
        )
    )
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
            con.say(&failure_text(&e));
            if unattended {
                finish(&con, true);
            }
            let _ = con.ask(
                &style::prompt("Press Enter to reboot and start again", None, None),
                None,
            );
            finish(&con, false)
        }
    }
}

/// The first lines: what this is, on what, and how it will boot.
fn header_text(build: &str, bios: bool, consoles: &[&str]) -> String {
    let right = match (build.is_empty(), crate::setup::machine()) {
        (true, m) => m,
        (false, m) if m.is_empty() => format!("build {build}"),
        (false, m) => format!("build {build}  {m}"),
    };
    format!(
        "{}\n  Firmware  {}\n  Consoles  {}",
        style::header("CoreRouter installer", &right),
        if bios {
            "BIOS: the disk boots through GRUB (and by UEFI, on such a machine)"
        } else {
            "UEFI: the disk gets a boot entry (and boots by BIOS too, via GRUB)"
        },
        consoles.join(", ")
    )
}

fn flow(
    con: &Console,
    opts: &BootOptions,
    cmdline: &str,
    auto: Option<Result<Auto, String>>,
) -> Result<bool, String> {
    let release = sys("/etc/os-release");
    let build = release
        .lines()
        .find_map(|l| l.strip_prefix("VERSION_ID="))
        .map(|v| style::ascii(v.trim_matches('"')))
        .unwrap_or_default();
    let bios = !Path::new("/sys/firmware/efi").exists();
    con.say(&header_text(&build, bios, &con.names()));
    for w in &opts.warnings {
        con.say(&style::block(
            2,
            &warn("WARNING"),
            9,
            &format!("kernel command line: {w}"),
        ));
    }

    con.say(&style::step(1, STEPS, "Medium"));
    let keys = package::load_keys(Path::new(KEYS));
    con.say("  Looking for the installer medium...");
    let (medium_dev, mut medium) = find_medium(con, &keys)?;
    let m = medium.header.manifest.clone();
    let version = style::ascii(&m.version);
    con.say(&format!(
        "  {}  {medium_dev}: CoreRouter {version} ({} channel)",
        good("OK"),
        style::ascii(&m.channel)
    ));
    con.say(&dim(&format!(
        "      commit {}, signed by key {}",
        style::ascii(&m.commit),
        style::ascii(&medium.key)
    )));
    let auto = match auto {
        Some(Ok(a)) => {
            con.say(&style::block(
                2,
                &warn("UNATTENDED INSTALL"),
                20,
                &format!(
                    "asked by the hypervisor (fw_cfg opt/org.corerouter/autoinstall): disk {}, no questions",
                    a.disk
                ),
            ));
            Some(a)
        }
        Some(Err(e)) => return Err(format!("unattended install (fw_cfg): {e}")),
        None => None,
    };
    loop {
        con.say(&style::step(2, STEPS, "Disk"));
        let ds = disks::list(&medium_dev, &medium.index, bios);
        con.say(&table(&ds));
        let pick = match &auto {
            Some(a) => ds
                .iter()
                .find(|d| d.name == a.disk)
                .ok_or_else(|| format!("no disk named {}", a.disk))?,
            None => {
                // One disk to offer: Enter takes it (nothing is written
                // before its name is typed). More, or none: Enter looks again.
                let only = match offered(&ds).as_slice() {
                    [d] => Some(*d),
                    _ => None,
                };
                let Some(line) = con.ask(
                    &style::prompt(
                        "Disk to install on",
                        only.map(|_| "1"),
                        Some(if only.is_some() {
                            "r = rescan, p = power off"
                        } else {
                            "number or name; r = rescan, p = power off"
                        }),
                    ),
                    None,
                ) else {
                    return Err("console closed".into());
                };
                match (line.as_str(), only) {
                    ("r", _) | ("", None) => continue,
                    ("p", _) => return Ok(true),
                    ("", Some(d)) => d,
                    (l, _) => {
                        let by_num = l
                            .parse::<usize>()
                            .ok()
                            .and_then(|n| offered(&ds).get(n.wrapping_sub(1)).copied());
                        match by_num.or_else(|| ds.iter().find(|d| d.name == l)) {
                            Some(d) => d,
                            None => {
                                con.say(&format!(
                                    "  No disk '{}'.",
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
            con.say(&style::block(
                2,
                "",
                0,
                &format!("{} cannot be the target: {r}.", pick.name),
            ));
            continue;
        }
        let keepable = pick.existing
            == Existing::CoreRouter {
                config_keepable: true,
            };
        let (keep, mgmt, append) = match &auto {
            Some(a) => (a.keep_config, a.mgmt.clone(), a.append.clone()),
            None => {
                con.say(&format!(
                    "  {}  {}: {}, {}",
                    good("OK"),
                    pick.name,
                    human(pick.bytes),
                    match &pick.existing {
                        Existing::Empty => "empty".to_owned(),
                        e => format!("holds {}", style::clip(&describe(e), 40)),
                    }
                ));
                let keep = keepable
                    && con
                        .ask(
                            &style::prompt(
                                "Keep the CoreRouter configuration that is on it?",
                                Some("y/N"),
                                None,
                            ),
                            None,
                        )
                        .is_some_and(|l| l.eq_ignore_ascii_case("y"));
                let Some(mgmt) = ask_mgmt(con) else {
                    return Err("console closed".into());
                };
                con.say(&style::step(4, STEPS, "Confirm"));
                con.say(&confirm_text(pick, &version, keep, mgmt.as_ref()));
                let typed = con.ask(
                    &style::prompt(
                        &format!("Type {} to erase it and install", pick.name),
                        None,
                        Some("anything else goes back"),
                    ),
                    None,
                );
                if typed.as_deref() != Some(pick.name.as_str()) {
                    con.say("  Nothing was written.");
                    continue;
                }
                (keep, mgmt, Vec::new())
            }
        };
        let running = format!("{cmdline} {}", append.join(" "));
        let poweroff = auto.as_ref().is_some_and(|a| a.poweroff);
        let rootfs_a = medium
            .index
            .part("rootfs-a")
            .map(|p| p.guid.clone())
            .unwrap_or_default();
        let line = slot_a_line(&rootfs_a, &m, &running, mgmt.as_ref());
        con.say(&style::step(5, STEPS, "Write"));
        let report = write(con, &mut medium, pick, keep, bios, &line)?;
        let ok = |text: &str| style::block(2, &good("OK"), 4, text);
        if bios {
            con.say(&ok(&format!(
                "BIOS boot: GRUB in the first blocks of {}, slot A",
                pick.name
            )));
        } else {
            match boot_entry(&report, &line) {
                Ok(line) => con.say(&ok(&line)),
                Err(e) => con.say(&style::block(
                    2,
                    &warn("WARNING"),
                    9,
                    &format!(
                        "boot entry: {e}. The firmware boots the disk by its removable-media \
                         path; the router makes its entries on the first boot."
                    ),
                )),
            }
        }
        con.say(&format!(
            "\n  {}",
            good(&format!(
                "OK  INSTALLED CoreRouter {version} on {} in {:.1} s{}",
                pick.name,
                report.total_ms as f64 / 1000.0,
                if report.kept_config {
                    ", configuration kept"
                } else {
                    ""
                }
            ))
        ));
        con.say(&next_text(
            report.kept_config,
            mgmt.as_ref(),
            auto.is_none(),
        ));
        con.say(&dim(&format!(
            "  {} MiB written in {} ms, read back in {} ms, sync {} ms",
            report.bytes_written >> 20,
            report.write_ms,
            report.verify_ms,
            report.sync_ms
        )));
        if auto.is_none() {
            let _ = con.ask(&style::prompt("Press Enter to reboot", None, None), None);
        }
        return Ok(poweroff);
    }
}

/// How the management address is typed in the installer.
const MGMT_FORM: &str = "  Form: <port> <address/prefix> [<gateway>]\n  \
     e.g. ether1 192.0.2.10/24 192.0.2.1\n  \
     None: the console asks for it on the first boot.";

/// Step 3: the management address for the first boot. `Some(None)`: none
/// (the console asks on the first boot); `None`: the console went.
fn ask_mgmt(con: &Console) -> Option<Option<Mgmt>> {
    con.say(&style::step(
        3,
        STEPS,
        "Management address for the first boot",
    ));
    // G1.6m: the names the router gives them on its first boot (bus
    // order), with link and MAC to find the cable.
    let nics = crate::setup::nics();
    if !nics.is_empty() {
        con.say(&crate::setup::nic_table(&nics, false));
    }
    con.say(MGMT_FORM);
    loop {
        let l = con.ask(
            &style::prompt("Management address", Some("none"), None),
            None,
        )?;
        if l.is_empty() {
            return Some(None);
        }
        match Mgmt::parse(&l.split_whitespace().collect::<Vec<_>>().join(",")) {
            Ok(m) if !nics.is_empty() && !nics.iter().any(|p| p.name == m.interface) => {
                con.say(&format!("  There is no port {} here.", m.interface));
            }
            Ok(m) => return Some(Some(m)),
            Err(e) => con.say(&style::block(2, "", 0, &format!("{e}. Try again."))),
        }
    }
}

fn write(
    con: &Console,
    medium: &mut Medium<File>,
    d: &Disk,
    keep: bool,
    bios: bool,
    line: &str,
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
    // The progress grows on one line, a mark every 10%: nothing is moved or
    // erased, so it reads the same on a screen, a serial log and a test.
    con.put(&format!("  Writing {}:", d.name));
    let threads = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let started = Instant::now();
    let mut shown = 0u64;
    let mut closed = false;
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
            bios_active: bios,
            bios_cmdline: Some(line.to_owned()),
        },
        &mut |done, total| {
            if closed {
                return;
            }
            let mark = done * 10 / total.max(1) * 10;
            if mark > shown {
                shown = mark;
                con.more(&format!(" {mark}%"));
            }
            if done >= total {
                closed = true;
                let s = started.elapsed().as_secs_f64().max(0.001);
                con.more(&format!(
                    "  {} MiB, {:.0} MiB/s\n",
                    total >> 20,
                    done as f64 / 1048576.0 / s
                ));
            }
        },
    );
    if !closed {
        con.more("\n");
    }
    let r = r?;
    con.say(&style::block(
        2,
        &good("OK"),
        4,
        "verified: ESP and /config by SHA-256, slot A by its dm-verity tree; partition table \
         written and read back",
    ));
    Ok(r)
}

/// What slot A's kernel is given, by the boot entry or by GRUB.
fn slot_a_line(
    rootfs_a: &str,
    m: &package::Manifest,
    running: &str,
    mgmt: Option<&Mgmt>,
) -> String {
    let tuning: Vec<(String, String)> = mgmt
        .map(|g| vec![("corerouter.mgmt".to_owned(), g.render())])
        .unwrap_or_default();
    install::slot_a_line(rootfs_a, m, running, &tuning)
}

/// The boot entry for the new disk.
fn boot_entry(r: &install::Report, line: &str) -> Result<String, String> {
    install::boot_entry(plan::EFIVARS.target, r, line)
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

    fn disk(
        name: &str,
        bytes: u64,
        model: &str,
        existing: Existing,
        refused: Option<&str>,
    ) -> Disk {
        Disk {
            name: name.into(),
            bytes,
            lbs: 512,
            model: model.into(),
            serial: "S5GXNX0T123456".into(),
            bus: "NVMe",
            removable: false,
            existing,
            refused: refused.map(str::to_owned),
        }
    }

    fn disks() -> Vec<Disk> {
        vec![
            disk(
                "nvme0n1",
                1000 << 30,
                "Samsung SSD 980 PRO 1TB with a long name",
                Existing::CoreRouter {
                    config_keepable: true,
                },
                None,
            ),
            disk(
                "sda",
                7 << 30,
                "",
                Existing::Unknown,
                Some("the installer medium"),
            ),
            disk(
                "mmcblk0",
                58 << 30,
                "DA4064",
                Existing::Gpt(vec![
                    "efi".into(),
                    "msr".into(),
                    "windows".into(),
                    "recovery".into(),
                ]),
                None,
            ),
            disk(
                "sdb",
                512 << 20,
                "Flash\u{1b}[2J",
                Existing::Empty,
                Some(
                    "smaller than the image needs (700 MiB) and a reason long enough to need a second line of its own on the screen",
                ),
            ),
        ]
    }

    #[test]
    fn the_disk_table_numbers_what_is_offered_and_explains_the_rest() {
        use crate::style::{render, tests::check};
        let t = table(&disks());
        check("disk table", &t);
        let plain = render(&t, false);
        let has = |s: &str| assert!(plain.contains(s), "{s:?} not in:\n{plain}");
        has("    #  NAME     SIZE       MODEL                  BUS       HOLDS");
        has("    1  nvme0n1  1000.0 GiB Samsung SSD 980 PRO 1~ NVMe      CoreRouter");
        has("    -  sda      7.0 GiB    -                      NVMe      data (MBR or a fi~");
        has("       not offered: the installer medium");
        has("    2  mmcblk0  58.0 GiB   DA4064                 NVMe      GPT: efi, msr, wi~");
        has("    -  sdb      512 MiB    Flash?[2J");
        // What is offered is bright, what is not is dimmed, reason included.
        let lit = render(&t, true);
        assert!(lit.contains("\u{1b}[1m  1  nvme0n1"), "{lit}");
        assert!(lit.contains("\u{1b}[2m  -  sda"), "{lit}");
        assert!(
            lit.contains("\u{1b}[2m       not offered: the installer medium"),
            "{lit}"
        );
        assert_eq!(offered(&disks()).len(), 2);
        check("no disk", &table(&[]));
        check("management form", MGMT_FORM);
        assert!(MGMT_FORM.contains("\n  e.g. ether1 192.0.2.10/24 192.0.2.1\n"));
    }

    #[test]
    fn the_confirmation_names_the_disk_and_what_goes_on_it() {
        use crate::style::{render, tests::check};
        let ds = disks();
        let m = Mgmt::parse("ether1,192.0.2.10/24,192.0.2.1").unwrap();
        let t = confirm_text(&ds[0], "0.1.0-dev.553", true, Some(&m));
        check("confirm", &t);
        let plain = render(&t, false);
        let has = |s: &str| assert!(plain.contains(s), "{s:?} not in:\n{plain}");
        has("  !! ALL DATA ON nvme0n1 WILL BE ERASED !!");
        has("  Disk     nvme0n1, 1000.0 GiB (1073741824000 bytes), NVMe");
        has("  Model    Samsung SSD 980 PRO 1TB with a long name");
        has("  Serial   S5GXNX0T123456");
        has("  Holds    CoreRouter: its configuration is kept, the rest is erased");
        has("  Install  CoreRouter 0.1.0-dev.553");
        has("  Address  192.0.2.10/24 on ether1, gateway 192.0.2.1");
        assert!(
            render(&t, true)
                .contains("\u{1b}[1;31m!! ALL DATA ON nvme0n1 WILL BE ERASED !!\u{1b}[0m")
        );
        let t = render(&confirm_text(&ds[2], "0.1.0", false, None), false);
        assert!(
            t.contains("  Holds    GPT: efi, msr, windows, recovery"),
            "{t}"
        );
        assert!(
            t.contains("  Address  none: the console asks for it on the first boot"),
            "{t}"
        );
        // Hostile disk strings stay text.
        check(
            "confirm, hostile",
            &confirm_text(&ds[3], "0.1.0", false, None),
        );
    }

    #[test]
    fn the_end_says_what_to_do_next_and_a_failure_says_why() {
        use crate::style::{render, tests::check};
        let m = Mgmt::parse("ether1,2001:db8::10/64").unwrap();
        let t = next_text(false, Some(&m), true);
        check("next", &t);
        let plain = render(&t, false);
        assert!(
            plain.contains("Next: remove the installation medium, then press Enter to reboot."),
            "{plain}"
        );
        assert!(
            plain.contains(
                "  Then open https://[2001:db8::10]/ (through ether1; user admin, no password"
            ),
            "{plain}"
        );
        // An unattended install asks for nothing.
        let t = render(&next_text(false, None, false), false);
        assert!(
            !t.contains("Enter") && t.contains("first boot the console asks"),
            "{t}"
        );
        let t = render(&next_text(true, None, true), false);
        assert!(t.contains("configuration that was kept"), "{t}");

        let f = failure_text(&format!(
            "/dev/sda: {}",
            "Device or resource busy ".repeat(8)
        ));
        check("failure", &f);
        let plain = render(&f, false);
        assert!(
            plain.contains("  FAILED  The install failed: /dev/sda: Device or resource busy"),
            "{plain}"
        );
        assert!(render(&f, true).contains("\u{1b}[1;31mFAILED\u{1b}[0m"));

        for bios in [false, true] {
            let h = header_text("1c0dfc09ec04", bios, &["tty1", "ttyS0"]);
            check("header", &h);
            let h = render(&h, false);
            assert!(
                h.contains("CoreRouter installer") && h.contains("build 1c0dfc09ec04"),
                "{h}"
            );
            assert!(
                h.contains(if bios {
                    "  Firmware  BIOS"
                } else {
                    "  Firmware  UEFI"
                }),
                "{h}"
            );
            assert!(h.contains("  Consoles  tty1, ttyS0"), "{h}");
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

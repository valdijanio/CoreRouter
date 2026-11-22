//! The whole A/B cycle on a directory that stands in for the router
//! (`Platform::lab`): the same code as on the image, with the firmware's
//! reboot simulated by `lab_reboot`. The QEMU version is
//! `cargo xtask os ab-test`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::path::{Path, PathBuf};

use corerouter_sysupdate::ab::{Boot, BootStore, Grub, Opts, Platform};
use corerouter_sysupdate::package::{self, Blob, Key, Manifest, Rootfs};
use corerouter_sysupdate::state::{Confirm, Reason, State};
use corerouter_sysupdate::{SlotId, verity};

fn tmp(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sysupdate-ab-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A package with a kernel of junk and a rootfs of `blocks` blocks.
fn package(
    dir: &Path,
    key: &[u8],
    version: &str,
    build: u64,
    seed: u8,
    config_format: u32,
) -> PathBuf {
    let kernel: Vec<u8> = (0..300_000u32).map(|i| (i as u8) ^ seed).collect();
    let data: Vec<u8> = (0..50 * 4096u32).map(|i| (i % 251) as u8 ^ seed).collect();
    let salt = vec![seed, 1, 2, 3];
    let tree = verity::tree(&data, &salt, 1).unwrap();
    let mut rootfs = data;
    rootfs.extend_from_slice(&tree.bytes);
    let m = Manifest {
        format: 1,
        version: version.into(),
        build,
        commit: format!("c{seed}"),
        channel: "stable".into(),
        kernel_version: "6.18.59".into(),
        config_format,
        kernel: Blob {
            size: kernel.len() as u64,
            sha256: package::sha256_hex(&kernel),
        },
        rootfs: Rootfs {
            size: rootfs.len() as u64,
            sha256: package::sha256_hex(&rootfs),
            data_blocks: tree.data_blocks,
            hash_blocks: tree.hash_blocks,
            salt: verity::hex(&salt),
            root_hash: verity::hex(&tree.root),
        },
    };
    let mut out = package::sign(&m, key).unwrap();
    out.extend_from_slice(&kernel);
    out.extend_from_slice(&rootfs);
    let p = dir.join(format!("{version}.crpkg"));
    std::fs::write(&p, out).unwrap();
    p
}

fn opts(reason: Reason) -> Opts {
    Opts {
        reason,
        confirm: Confirm::Auto,
        timeout_s: 300,
        tuning: vec![("iommu".into(), "pt".into())],
        mgmt: vec!["ether1".into()],
        now: 100,
        pipelined: true,
        threads: 2,
        config_format: 1,
        drill: false,
    }
}

struct Lab {
    dir: PathBuf,
    p: Platform,
    key: Vec<u8>,
}

fn lab(name: &str) -> Lab {
    make(name, Platform::lab)
}

/// The same box, booted by BIOS through GRUB's files (G1.6g).
fn lab_bios(name: &str) -> Lab {
    make(&format!("{name}-bios"), Platform::lab_bios)
}

type NewPlatform = fn(&Path, &Path, Vec<Key>, u64) -> Result<Platform, String>;

fn make(name: &str, new: NewPlatform) -> Lab {
    let dir = tmp(name);
    let key = package::generate_key().unwrap();
    let keys = vec![Key::from_hex(&package::public_hex(&key).unwrap()).unwrap()];
    let config = dir.join("config");
    std::fs::create_dir_all(&config).unwrap();
    std::fs::write(
        config.join("running.json"),
        r#"{"format_version":1,"v":"a"}"#,
    )
    .unwrap();
    let mut p = new(&dir.join("box"), &config, keys, 4 << 20).unwrap();
    // The factory image in slot A, booted by the fallback path (built-in
    // command line), then the first boot provisions the entries.
    assert!(p.lab_seed("1.0", 10).unwrap());
    assert!(!p.lab_seed("1.0", 10).unwrap(), "seeded once");
    assert_eq!(p.running(), Some(SlotId::A));
    assert_eq!(p.status(&State::default())["slots"][0]["state"], "running");
    assert!(
        p.provision(&["iommu", "isolcpus"]).unwrap().is_empty(),
        "already provisioned"
    );
    Lab { dir, p, key }
}

/// Writes the configuration as the storage does: a new file renamed over
/// the old one (the snapshot links it, G1.6u).
fn save(config: &Path, text: &str) {
    std::fs::write(config.join("running.json.tmp"), text).unwrap();
    std::fs::rename(config.join("running.json.tmp"), config.join("running.json")).unwrap();
}

/// The status without what moves on its own (free bytes of `/config`).
fn fixed(mut v: serde_json::Value) -> serde_json::Value {
    if let Some(o) = v.as_object_mut() {
        o.remove("config_space");
    }
    v
}

fn st(p: &Platform) -> State {
    State::load(&p.state_dir()).0
}

#[test]
fn update_confirm_and_status() {
    update_confirm_and_status_on(lab("ok"));
}

#[test]
fn bios_update_confirm_and_status() {
    update_confirm_and_status_on(lab_bios("ok"));
}

fn update_confirm_and_status_on(mut l: Lab) {
    let b = package(&l.dir, &l.key, "1.1", 20, 2, 1);
    let mut last = (0, 0);
    let rep =
        l.p.install(&b, false, &opts(Reason::Update), &mut |n, t| last = (n, t))
            .unwrap();
    assert_eq!(rep.slot, Some(SlotId::B));
    assert_eq!(last.0, last.1);
    assert!(rep.cmdline.contains("corerouter.slot=b") && rep.cmdline.contains("iommu=pt"));
    assert!(rep.cmdline.ends_with("panic=10"));
    let s = l.p.status(&st(&l.p));
    assert_eq!(s["slots"][1]["state"], "trial");
    assert_eq!(s["slots"][1]["next"], true);
    assert_eq!(s["slots"][0]["state"], "running");
    // A second update while the trial is armed is refused.
    assert!(
        l.p.install(&b, false, &opts(Reason::Update), &mut |_, _| {})
            .unwrap_err()
            .contains("pending")
    );

    let (boot, log) = l.p.lab_reboot().unwrap();
    assert!(
        matches!(
            boot,
            Boot::Trial {
                slot: SlotId::B,
                ..
            }
        ),
        "{log:?}"
    );
    assert_eq!(l.p.running(), Some(SlotId::B));
    assert!(l.p.running_verified());
    l.p.confirm(200, "healthy").unwrap();
    let s = l.p.status(&st(&l.p));
    assert_eq!(s["primary"], "b");
    assert_eq!(s["last"]["result"], "confirmed");
    assert_eq!(s["slots"][0]["state"], "standby");
    assert_eq!(s["slots"][1]["version"], "1.1");
    // The next reboot stays on B.
    let (boot, _) = l.p.lab_reboot().unwrap();
    assert_eq!(boot, Boot::Normal);
    assert_eq!(l.p.running(), Some(SlotId::B));
    // A scrub of both slots passes.
    l.p.scrub(SlotId::A, 2).unwrap();
    l.p.scrub(SlotId::B, 2).unwrap();
    // Older than running: refused by update, taken by downgrade.
    let old = package(&l.dir, &l.key, "0.9", 5, 3, 1);
    assert!(
        l.p.install(&old, false, &opts(Reason::Update), &mut |_, _| {})
            .unwrap_err()
            .contains("downgrade")
    );
    let _ = std::fs::remove_dir_all(&l.dir);
}

#[test]
fn unconfirmed_trial_rolls_back_with_the_configuration() {
    unconfirmed_trial_rolls_back_with_the_configuration_on(lab("rollback"));
}

#[test]
fn bios_unconfirmed_trial_rolls_back_with_the_configuration() {
    unconfirmed_trial_rolls_back_with_the_configuration_on(lab_bios("rollback"));
}

fn unconfirmed_trial_rolls_back_with_the_configuration_on(mut l: Lab) {
    let b = package(&l.dir, &l.key, "1.1", 20, 2, 1);
    l.p.install(&b, false, &opts(Reason::Update), &mut |_, _| {})
        .unwrap();
    l.p.lab_reboot().unwrap();
    // The trial slot rewrites the configuration, then never confirms: the
    // deadline (init) reboots, and the firmware boots BootOrder = A.
    save(&l.p.config, r#"{"format_version":2,"v":"b"}"#);
    let (boot, log) = l.p.lab_reboot().unwrap();
    assert_eq!(boot, Boot::Normal);
    assert_eq!(l.p.running(), Some(SlotId::A));
    assert!(log.iter().any(|x| x.contains("not confirmed")), "{log:?}");
    assert_eq!(
        std::fs::read_to_string(l.p.config.join("running.json")).unwrap(),
        r#"{"format_version":1,"v":"a"}"#
    );
    let s = l.p.status(&st(&l.p));
    assert_eq!(s["last"]["result"], "rolled-back");
    assert_eq!(s["slots"][1]["state"], "failed");
    assert_eq!(s["primary"], "a");
    let _ = std::fs::remove_dir_all(&l.dir);
}

#[test]
fn bad_packages_are_refused_before_anything_changes() {
    let l = lab("bad");
    let other = package::generate_key().unwrap();
    let foreign = package(&l.dir, &other, "1.1", 20, 2, 1);
    let before = fixed(l.p.status(&st(&l.p)));
    let e =
        l.p.install(&foreign, false, &opts(Reason::Update), &mut |_, _| {})
            .unwrap_err();
    assert!(e.contains("does not trust"), "{e}");
    assert_eq!(fixed(l.p.status(&st(&l.p))), before);
    // Signed, but the payload was changed after signing.
    let good = package(&l.dir, &l.key, "1.2", 30, 4, 1);
    let mut bytes = std::fs::read(&good).unwrap();
    let n = bytes.len();
    bytes[n - 5000] ^= 0xff;
    std::fs::write(&good, &bytes).unwrap();
    let e =
        l.p.install(&good, false, &opts(Reason::Update), &mut |_, _| {})
            .unwrap_err();
    assert!(e.contains("signed hashes"), "{e}");
    let s = l.p.status(&st(&l.p));
    assert_eq!(s["slots"][1]["state"], "empty");
    assert_eq!(s["slots"][1]["next"], false);
    assert!(st(&l.p).trial.is_none());
    // Truncated file.
    std::fs::write(&good, &bytes[..n - 1]).unwrap();
    assert!(
        l.p.install(&good, false, &opts(Reason::Update), &mut |_, _| {})
            .is_err()
    );
    let _ = std::fs::remove_dir_all(&l.dir);
}

#[test]
fn boot_parameter_that_does_not_boot_falls_back() {
    boot_parameter_that_does_not_boot_falls_back_on(lab("drill"));
}

#[test]
fn bios_boot_parameter_that_does_not_boot_falls_back() {
    boot_parameter_that_does_not_boot_falls_back_on(lab_bios("drill"));
}

fn boot_parameter_that_does_not_boot_falls_back_on(mut l: Lab) {
    let mut o = opts(Reason::BootParams);
    o.tuning = vec![("isolcpus".into(), "1".into())];
    o.drill = true;
    let rep = l.p.clone_running(&o, &mut |_, _| {}).unwrap();
    assert!(rep.copied);
    assert!(
        rep.cmdline.contains("isolcpus=1")
            && rep.cmdline.contains(corerouter_sysupdate::DRILL_INIT)
    );
    // The running slot's entry did not change.
    let s = l.p.status(&st(&l.p));
    assert!(
        !s["slots"][0]["cmdline"]
            .as_str()
            .unwrap()
            .contains("isolcpus")
    );
    let (boot, log) = l.p.lab_reboot().unwrap();
    assert_eq!(boot, Boot::Normal, "{log:?}");
    assert_eq!(l.p.running(), Some(SlotId::A));
    assert!(log.iter().any(|x| x.contains("did not come up")), "{log:?}");
    // Without the drill, the same image is not copied again.
    o.drill = false;
    let rep = l.p.clone_running(&o, &mut |_, _| {}).unwrap();
    assert!(!rep.copied);
    let (boot, _) = l.p.lab_reboot().unwrap();
    assert!(matches!(
        boot,
        Boot::Trial {
            slot: SlotId::B,
            ..
        }
    ));
    let _ = std::fs::remove_dir_all(&l.dir);
}

#[test]
fn downgrade_back_to_the_previous_slot_takes_its_configuration() {
    downgrade_back_to_the_previous_slot_takes_its_configuration_on(lab("down"));
}

#[test]
fn bios_downgrade_back_to_the_previous_slot_takes_its_configuration() {
    downgrade_back_to_the_previous_slot_takes_its_configuration_on(lab_bios("down"));
}

fn downgrade_back_to_the_previous_slot_takes_its_configuration_on(mut l: Lab) {
    let b = package(&l.dir, &l.key, "2.0", 20, 2, 2);
    l.p.install(&b, false, &opts(Reason::Update), &mut |_, _| {})
        .unwrap();
    l.p.lab_reboot().unwrap();
    l.p.confirm(200, "ok").unwrap();
    // 2.0 migrated the configuration to format 2.
    save(&l.p.config, r#"{"format_version":2,"v":"b"}"#);
    let mut o = opts(Reason::Downgrade);
    o.config_format = 2;
    let rep = l.p.switch_back(&o).unwrap();
    assert_eq!(rep.slot, Some(SlotId::A));
    let (boot, log) = l.p.lab_reboot().unwrap();
    assert!(
        matches!(
            boot,
            Boot::Trial {
                slot: SlotId::A,
                ..
            }
        ),
        "{log:?}"
    );
    // Slot A runs with the configuration it had (format 1).
    assert_eq!(
        std::fs::read_to_string(l.p.config.join("running.json")).unwrap(),
        r#"{"format_version":1,"v":"a"}"#
    );
    l.p.confirm(300, "ok").unwrap();
    assert_eq!(l.p.status(&st(&l.p))["primary"], "a");
    // Nothing older left: downgrade refused.
    assert!(l.p.switch_back(&o).unwrap_err().contains("not older"));
    let _ = std::fs::remove_dir_all(&l.dir);
}

/// G1.6e: the package arrives in chunks (the control channel) and goes to
/// the slot as it comes, through the same install.
fn stream(
    l: &Lab,
    bytes: Vec<u8>,
    declared: u64,
    stop_at: Option<usize>,
) -> Result<corerouter_sysupdate::ab::Report, String> {
    use corerouter_sysupdate::upload::ChunkReader;
    let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<u8>>(2);
    let feeder = std::thread::spawn(move || {
        for (i, c) in bytes.chunks(64 << 10).enumerate() {
            if stop_at == Some(i) {
                return; // the client went away
            }
            if tx.send(c.to_vec()).is_err() {
                return;
            }
        }
    });
    let mut r = ChunkReader::new(rx, declared, std::time::Duration::from_secs(5));
    let out = l.p.install_from(
        &mut r,
        Some(declared),
        false,
        &opts(Reason::Update),
        &mut |_, _| {},
    );
    drop(r);
    feeder.join().unwrap();
    out
}

#[test]
fn streamed_install_and_its_failures() {
    let mut l = lab("stream");
    let b = std::fs::read(package(&l.dir, &l.key, "1.1", 20, 2, 1)).unwrap();
    let n = b.len() as u64;
    let before = l.p.status(&st(&l.p));
    // Declared size different from the manifest's: refused after the header.
    let e = stream(&l, b.clone(), n + 1, None).unwrap_err();
    assert!(e.contains("manifest says"), "{e}");
    // Aborted in the middle: an error, slot B not activated, no trial.
    let e = stream(&l, b.clone(), n, Some(3)).unwrap_err();
    assert!(e.contains("aborted after"), "{e}");
    assert!(st(&l.p).trial.is_none());
    assert_eq!(l.p.status(&st(&l.p))["slots"][1]["next"], false);
    assert_eq!(l.p.status(&st(&l.p))["slots"][0], before["slots"][0]);
    // Tampered on the way.
    let mut bad = b.clone();
    let at = bad.len() - 7000;
    bad[at] ^= 1;
    let e = stream(&l, bad, n, None).unwrap_err();
    assert!(e.contains("signed hashes"), "{e}");
    assert!(st(&l.p).trial.is_none());
    // Whole: same result as from a file, trial armed and boots.
    let rep = stream(&l, b.clone(), n, None).unwrap();
    assert_eq!(rep.slot, Some(SlotId::B));
    assert_eq!(l.p.status(&st(&l.p))["slots"][1]["state"], "trial");
    let (boot, _) = l.p.lab_reboot().unwrap();
    assert!(matches!(
        boot,
        Boot::Trial {
            slot: SlotId::B,
            ..
        }
    ));
    // check() on a stream says the same as on the file.
    let mut src = b.as_slice();
    let c = corerouter_sysupdate::upload::check(&mut src, Some(n), &l.p.keys).unwrap();
    assert_eq!(
        (c["version"].as_str(), c["intact"].as_bool()),
        (Some("1.1"), Some(true))
    );
    let _ = std::fs::remove_dir_all(&l.dir);
}

// G1.6g: what only GRUB's files do.

fn grub(l: &Lab) -> PathBuf {
    l.dir.join("box/esp/corerouter")
}

#[test]
fn bios_status_says_bios_and_names_the_cfg() {
    let l = lab_bios("fw");
    let s = l.p.status(&st(&l.p));
    assert_eq!(s["firmware"], "bios");
    assert_eq!(s["primary"], "a");
    assert_eq!(s["slots"][0]["boot_entry"], "corerouter/a.cfg");
    assert!(s["slots"][1]["boot_entry"].is_null());
    let c = s["slots"][0]["cmdline"].as_str().unwrap();
    assert!(
        c.contains("dm-mod.create=\"") && c.ends_with("panic=10"),
        "{c}"
    );
    assert_eq!(lab("fw").p.status(&State::default())["firmware"], "uefi");
}

/// A value GRUB would read as script never reaches a `.cfg`, and the box stays
/// as it was. (Whitespace is the engine's to refuse: here it is one more word,
/// inside its own quotes, `biosboot::hostile_parameters_stay_data`.)
#[test]
fn bios_hostile_boot_parameter_is_refused() {
    let l = lab_bios("hostile");
    let before = std::fs::read(grub(&l).join("a.cfg")).unwrap();
    for bad in ["1' ; reboot ; '", "1\\", "1\"x"] {
        let mut o = opts(Reason::BootParams);
        o.tuning = vec![("isolcpus".into(), bad.into())];
        let err = l.p.clone_running(&o, &mut |_, _| {});
        assert!(err.is_err(), "{bad:?} went through");
        assert!(!grub(&l).join("b.cfg").exists(), "{bad:?}");
        assert!(l.p.status(&st(&l.p))["slots"][1]["next"] == false);
    }
    assert_eq!(std::fs::read(grub(&l).join("a.cfg")).unwrap(), before);
    let _ = std::fs::remove_dir_all(&l.dir);
}

/// A block GRUB cannot rewrite: it boots the primary and the next boot's
/// init sees `next=` still there.
#[test]
fn bios_grubenv_that_cannot_be_written_means_no_trial() {
    let mut l = lab_bios("readonly");
    let b = package(&l.dir, &l.key, "1.1", 20, 2, 1);
    l.p.install(&b, false, &opts(Reason::Update), &mut |_, _| {})
        .unwrap();
    std::fs::write(l.dir.join("box/lab-grubenv-readonly"), "").unwrap();
    let (boot, log) = l.p.lab_reboot().unwrap();
    assert_eq!(l.p.running(), Some(SlotId::A), "{log:?}");
    assert_eq!(boot, Boot::Normal, "{log:?}");
    let last = l.p.status(&st(&l.p));
    let detail = last["last"]["detail"].as_str().unwrap();
    assert!(detail.contains("cannot run a trial boot"), "{detail}");
    assert!(l.p.status(&st(&l.p))["slots"][1]["next"] == false);
    let _ = std::fs::remove_dir_all(&l.dir);
}

/// Each point of a power cut: the old block, the new block or garbage where
/// the block was; the box boots something and goes back to one primary.
#[test]
fn bios_power_cut_around_grubenv() {
    let mut l = lab_bios("cut");
    let b = package(&l.dir, &l.key, "1.1", 20, 2, 1);
    l.p.install(&b, false, &opts(Reason::Update), &mut |_, _| {})
        .unwrap();
    let env = grub(&l).join("grubenv");
    // Before the `next=` block: the old one, no trial.
    std::fs::write(
        &env,
        corerouter_sysupdate::biosboot::grubenv(SlotId::A, None),
    )
    .unwrap();
    let (_, log) = l.p.lab_reboot().unwrap();
    assert_eq!(l.p.running(), Some(SlotId::A), "{log:?}");
    // A block that is not one: slot A by default, and repaired.
    std::fs::write(&env, [0xFF; 512]).unwrap();
    let (_, log) = l.p.lab_reboot().unwrap();
    assert_eq!(l.p.running(), Some(SlotId::A), "{log:?}");
    assert_eq!(l.p.status(&st(&l.p))["primary"], serde_json::Value::Null);
    l.p.provision(&[]).unwrap();
    assert_eq!(l.p.status(&st(&l.p))["primary"], "a");
    let _ = std::fs::remove_dir_all(&l.dir);
}

#[test]
fn bios_primary_without_kernel_or_cfg_falls_to_the_other_slot() {
    let mut l = lab_bios("fall");
    let b = package(&l.dir, &l.key, "1.1", 20, 2, 1);
    l.p.install(&b, false, &opts(Reason::Update), &mut |_, _| {})
        .unwrap();
    l.p.lab_reboot().unwrap();
    l.p.confirm(200, "healthy").unwrap();
    assert_eq!(l.p.status(&st(&l.p))["primary"], "b");
    std::fs::remove_file(grub(&l).join("b.cfg")).unwrap();
    let (_, log) = l.p.lab_reboot().unwrap();
    assert_eq!(l.p.running(), Some(SlotId::A), "{log:?}");
    let _ = std::fs::remove_dir_all(&l.dir);
}

/// Updated under UEFI, the disk keeps GRUB's files true: the disk moved to a
/// BIOS boots the new image and not a verity hash that is gone.
#[test]
fn uefi_update_keeps_grub_files_for_a_move_to_bios() {
    let mut l = lab("mirror");
    let g = grub(&l);
    std::fs::create_dir_all(&g).unwrap();
    std::fs::write(g.join("grub.cfg"), corerouter_sysupdate::biosboot::GRUB_CFG).unwrap();
    let b = package(&l.dir, &l.key, "1.1", 20, 2, 1);
    let rep =
        l.p.install(&b, false, &opts(Reason::Update), &mut |_, _| {})
            .unwrap();
    l.p.lab_reboot().unwrap();
    l.p.confirm(200, "healthy").unwrap();
    assert_eq!(l.p.status(&st(&l.p))["primary"], "b");
    let env = std::fs::read(g.join("grubenv")).unwrap();
    assert_eq!(
        corerouter_sysupdate::biosboot::parse_env(&env),
        Some((Some(SlotId::B), None))
    );
    let cfg = std::fs::read(g.join("b.cfg")).unwrap();
    assert_eq!(
        corerouter_sysupdate::biosboot::slot_cmdline(&cfg).as_deref(),
        Some(rep.cmdline.as_str())
    );
    let _ = std::fs::remove_dir_all(&l.dir);
}

/// Updated on one firmware, then the other, and back to the first one's
/// NVRAM: the entry of the slot that moved is rewritten.
#[test]
fn entry_written_under_the_other_firmware_is_refreshed() {
    let mut l = lab("moved");
    let g = grub(&l);
    std::fs::create_dir_all(&g).unwrap();
    std::fs::write(g.join("grub.cfg"), corerouter_sysupdate::biosboot::GRUB_CFG).unwrap();
    let uefi = l.p.boot.clone();
    let b = package(&l.dir, &l.key, "1.1", 20, 2, 1);
    l.p.install(&b, false, &opts(Reason::Update), &mut |_, _| {})
        .unwrap();
    l.p.lab_reboot().unwrap();
    l.p.confirm(200, "healthy").unwrap();
    // To a BIOS: the trial goes to slot A, whose Boot#### does not change.
    l.p.boot = BootStore::Bios(Grub {
        esp_dir: l.dir.join("box/esp"),
        remount: false,
    });
    let (_, log) = l.p.lab_reboot().unwrap();
    assert_eq!(l.p.running(), Some(SlotId::B), "{log:?}");
    let c = package(&l.dir, &l.key, "1.2", 30, 3, 1);
    let rep =
        l.p.install(&c, false, &opts(Reason::Update), &mut |_, _| {})
            .unwrap();
    l.p.lab_reboot().unwrap();
    l.p.confirm(200, "healthy").unwrap();
    assert_eq!(l.p.running(), Some(SlotId::A));
    let bios_line = rep.cmdline;
    // Back on the old NVRAM: running slot B by its old order.
    l.p.boot = uefi;
    let (_, log) = l.p.lab_reboot().unwrap();
    assert_eq!(l.p.running(), Some(SlotId::B), "{log:?}");
    let before = l.p.status(&st(&l.p));
    assert_ne!(before["slots"][0]["cmdline"], bios_line.as_str());
    let wrote = l.p.provision(&["iommu", "isolcpus"]).unwrap();
    assert!(wrote.iter().any(|x| x.contains("slot a")), "{wrote:?}");
    let after = l.p.status(&st(&l.p));
    assert_eq!(after["slots"][0]["cmdline"], bios_line.as_str());
    let _ = std::fs::remove_dir_all(&l.dir);
}

/// G1.6zm: an entry naming another ESP (written while this disk's ESP had
/// the image's GUID, or by another image over this disk) is written anew
/// for this ESP, in its place; the status says which ESP that is.
#[test]
fn an_entry_naming_another_esp_is_written_anew() {
    let mut l = lab("esp-guid");
    let own = l.p.esp.guid.clone();
    let before = l.p.status(&st(&l.p));
    assert_eq!(before["esp_guid"], own.as_str());
    // The disk is written over and boots with another ESP GUID: the entries
    // still name the old one.
    l.p.esp.guid = "0d2c41a7-1b6e-4c3e-9d1f-5a7b8c9d0e1f".into();
    let wrote = l.p.provision(&[]).unwrap();
    assert!(wrote.iter().any(|x| x.contains("slot a")), "{wrote:?}");
    let after = l.p.status(&st(&l.p));
    assert_eq!(after["esp_guid"], "0d2c41a7-1b6e-4c3e-9d1f-5a7b8c9d0e1f");
    assert_eq!(
        after["slots"][0]["boot_entry"], before["slots"][0]["boot_entry"],
        "the same Boot#### number"
    );
    assert!(l.p.provision(&[]).unwrap().is_empty(), "then nothing to do");
    let _ = std::fs::remove_dir_all(&l.dir);
}

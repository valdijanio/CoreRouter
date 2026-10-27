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

use corerouter_sysupdate::ab::{Boot, Opts, Platform};
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
    let mut p = Platform::lab(&dir.join("box"), &config, keys, 4 << 20).unwrap();
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

fn st(p: &Platform) -> State {
    State::load(&p.state_dir()).0
}

#[test]
fn update_confirm_and_status() {
    let mut l = lab("ok");
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
    let mut l = lab("rollback");
    let b = package(&l.dir, &l.key, "1.1", 20, 2, 1);
    l.p.install(&b, false, &opts(Reason::Update), &mut |_, _| {})
        .unwrap();
    l.p.lab_reboot().unwrap();
    // The trial slot rewrites the configuration, then never confirms: the
    // deadline (init) reboots, and the firmware boots BootOrder = A.
    std::fs::write(
        l.p.config.join("running.json"),
        r#"{"format_version":2,"v":"b"}"#,
    )
    .unwrap();
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
    let before = l.p.status(&st(&l.p));
    let e =
        l.p.install(&foreign, false, &opts(Reason::Update), &mut |_, _| {})
            .unwrap_err();
    assert!(e.contains("does not trust"), "{e}");
    assert_eq!(l.p.status(&st(&l.p)), before);
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
    let mut l = lab("drill");
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
    let mut l = lab("down");
    let b = package(&l.dir, &l.key, "2.0", 20, 2, 2);
    l.p.install(&b, false, &opts(Reason::Update), &mut |_, _| {})
        .unwrap();
    l.p.lab_reboot().unwrap();
    l.p.confirm(200, "ok").unwrap();
    // 2.0 migrated the configuration to format 2.
    std::fs::write(
        l.p.config.join("running.json"),
        r#"{"format_version":2,"v":"b"}"#,
    )
    .unwrap();
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

//! G1.6k: `cargo xtask os frr-test` — the image's FRR driven by hal-frr
//! between two routers, in QEMU as the user (no root, no tap):
//!
//! - two guests of `disk.img` (throw-away qcow2 overlays, their own NVRAM),
//!   booted the factory way with the maintenance shell on the serial
//!   console; their `ether1`s are one link, a QEMU UDP socket pair on the
//!   host's loopback;
//! - each is configured only through commands (`corerouter-init run`, the
//!   same `Session::execute` as the CLI and MCP): an address on `ether1` and a
//!   loopback /32, OSPFv2 point-to-point, Segment Routing with a
//!   prefix SID for the loopback, MPLS input and LDP on `ether1` (no TI-LFA:
//!   off in production while G3.4l is open), a BFD peer on the link;
//! - what must follow is read back from FRR through hal-frr's queries: the
//!   OSPF adjacency Full (ospfd), the other router's prefix SID with its
//!   label (ospfd's SR database), the LDP session operational (ldpd), the
//!   BFD session up (bfdd's, run by the daemon's engine as its data
//!   plane), labels in the kernel's MPLS table (zebra), the
//!   other loopback answering ping over the OSPF route;
//! - the FRR version the daemons report must be the one
//!   `os/buildroot-patches` pins, and the RSS of each daemon is printed;
//! - G1.6i: before the configuration only mgmtd, zebra and staticd run;
//!   on r1 a BGP instance starts bgpd, and removing LDP and the BFD peer
//!   stops ldpd and bfdd while zebra and ospfd keep their PIDs and the
//!   other loopback still answers over OSPF.

#![allow(clippy::indexing_slicing)]

use std::path::Path;
use std::process::Command;
use std::time::Instant;

use serde_json::Value;

use super::ab::{Numbers, Vm, check, fresh_vars, qemu_base, ready_s, start};
use super::install::{sh, until};

/// The FRR daemons corerouter-init can start (`docs/os-image.md`); bgpd,
/// ospfd, ospf6d, ldpd and bfdd only while the configuration uses them.
const DAEMONS: &str = "mgmtd zebra staticd bgpd ospfd ospf6d ldpd bfdd";

/// The on-demand daemons running now (`pidof`, empty when none).
fn on_demand_running(vm: &mut Vm, log: &mut std::fs::File) -> Result<String, String> {
    let out = sh(
        vm,
        log,
        "{ for p in bgpd ospfd ospf6d ldpd bfdd; do pidof $p >/dev/null && printf '%s ' $p; done; echo .; }",
    )?;
    Ok(out.trim().trim_end_matches('.').trim().to_owned())
}

/// Waits up to 10 s until `daemon` runs (`up`) or is gone.
fn wait_daemon(vm: &mut Vm, log: &mut std::fs::File, daemon: &str, up: bool) -> Result<(), String> {
    let want = if up { "0" } else { "1" };
    let out = sh(
        vm,
        log,
        &format!(
            "{{ i=0; while [ $i -lt 50 ]; do pidof {daemon} >/dev/null; [ $? = {want} ] && break; \
             sleep 0.2; i=$((i+1)); done; pidof {daemon} >/dev/null; [ $? = {want} ] && echo DONE; echo .; }}"
        ),
    )?;
    check(
        out.contains("DONE"),
        format!(
            "{daemon} did not {} in 10 s",
            if up { "start" } else { "stop" }
        ),
    )
}

/// G1.6i on r1, after `verify`: daemons follow the configuration, and
/// stopping one does not touch the others nor the routes.
fn on_demand(vm: &mut Vm, log: &mut std::fs::File, nums: &mut Numbers) -> Result<(), String> {
    let base = sh(vm, log, "pidof zebra ospfd")?;
    vm.ok(
        log,
        "routing.bgp.instance.set",
        r#"{"asn":65001,"router_id":"10.255.0.1"}"#,
    )?;
    wait_daemon(vm, log, "bgpd", true)?;
    nums.put("r1: with a BGP instance", on_demand_running(vm, log)?);
    // A disabled instance stays in bgpd (`bgp shutdown`): bgpd stays.
    vm.ok(log, "mpls.ldp.remove", "{}")?;
    wait_daemon(vm, log, "ldpd", false)?;
    vm.ok(log, "routing.bfd.peer.remove", r#"{"id":"10.0.12.2"}"#)?;
    wait_daemon(vm, log, "bfdd", false)?;
    nums.put(
        "r1: LDP and the BFD peer removed",
        on_demand_running(vm, log)?,
    );
    let after = sh(vm, log, "pidof zebra ospfd")?;
    check(
        after.trim() == base.trim(),
        format!("zebra/ospfd restarted: {} → {}", base.trim(), after.trim()),
    )?;
    let ping = sh(vm, log, "ping -c 3 -W 2 10.255.0.2 | tail -n 2")?;
    check(
        ping.contains(" 0% packet loss"),
        format!("r1: ping 10.255.0.2 after stopping ldpd and bfdd: {ping}"),
    )?;
    nums.put("r1: OSPF route kept (zebra, ospfd PIDs unchanged)", ping);
    Ok(())
}

/// The FRR version `os/buildroot-patches/*.patch` sets (`+FRR_VERSION = x`),
/// if a patch moves FRR off Buildroot's own.
fn pinned_frr(os: &Path) -> Result<Option<String>, String> {
    let (patches, _) = super::buildroot_patches(os)?;
    for p in patches {
        let text = std::fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        if let Some(v) = text.lines().find_map(|l| l.strip_prefix("+FRR_VERSION = ")) {
            return Ok(Some(v.trim().to_owned()));
        }
    }
    Ok(None)
}

/// Router `n` (1 or 2): booted, its shell up.
fn boot(
    work: &Path,
    images: &Path,
    kvm: bool,
    log: &mut std::fs::File,
    n: u8,
    ports: (u16, u16),
) -> Result<Vm, String> {
    let disk = work.join(format!("r{n}.qcow2"));
    let _ = std::fs::remove_file(&disk);
    let st = Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2", "-F", "raw", "-b"])
        .arg(images.join("disk.img"))
        .arg(&disk)
        .status()
        .map_err(|e| format!("qemu-img: {e}"))?;
    check(st.success(), "qemu-img create failed")?;
    let vars = work.join(format!("r{n}-vars.fd"));
    fresh_vars(&vars)?;
    let mut cmd = qemu_base(kvm, &vars);
    cmd.arg("-drive")
        .arg(format!("file={},if=virtio,format=qcow2", disk.display()));
    // One link: each side sends to the other's UDP port.
    let (local, remote) = if n == 1 { ports } else { (ports.1, ports.0) };
    cmd.arg("-netdev").arg(format!(
        "socket,id=l0,udp=127.0.0.1:{remote},localaddr=127.0.0.1:{local}"
    ));
    cmd.arg("-device")
        .arg(format!("virtio-net-pci,netdev=l0,mac=52:54:00:16:0b:0{n}"));
    // The factory boot (as ab-test's): the kernel QEMU hands OVMF, with the
    // maintenance shell; FRR and the daemon are the installed image's.
    cmd.arg("-kernel").arg(images.join("bzImage"));
    cmd.arg("-append").arg("corerouter.shell=ttyS0");
    start(log, &format!("r{n}"), cmd)
}

/// The commands that make router `n` an OSPF/SR/LDP/BFD core router.
fn configure(vm: &mut Vm, log: &mut std::fs::File, n: u8) -> Result<(), String> {
    let other = 3 - n;
    let steps: [(&str, String); 13] = [
        // A port discovered down starts disabled (as the installer's
        // management address does it, `corerouter-init` plan.rs).
        (
            "interface.set",
            r#"{"name":"ether1","disabled":false}"#.into(),
        ),
        // The kernel's `lo` (G3.4i: ospfd takes a prefix SID only there).
        ("interface.loopback.add", r#"{"name":"lo"}"#.into()),
        (
            "ip.address.add",
            format!(r#"{{"address":"10.0.12.{n}/24","interface":"ether1"}}"#),
        ),
        (
            "ip.address.add",
            format!(r#"{{"address":"10.255.0.{n}/32","interface":"lo"}}"#),
        ),
        (
            "routing.ospf.instance.add",
            format!(r#"{{"name":"core","router_id":"10.255.0.{n}"}}"#),
        ),
        (
            "routing.ospf.area.add",
            r#"{"name":"backbone","instance":"core","area_id":"0.0.0.0"}"#.into(),
        ),
        (
            "routing.ospf.interface-template.add",
            r#"{"area":"backbone","interfaces":"ether1","type":"ptp","hello_interval":1,"dead_interval":4}"#.into(),
        ),
        (
            "routing.ospf.interface-template.add",
            r#"{"area":"backbone","interfaces":"lo","passive":true}"#.into(),
        ),
        ("mpls.interface.add", r#"{"interface":"ether1"}"#.into()),
        (
            "routing.ospf.segment-routing.set",
            r#"{"instance":"core","force":true}"#.into(),
        ),
        (
            "mpls.ldp.add",
            format!(r#"{{"lsr_id":"10.255.0.{n}"}}"#),
        ),
        ("mpls.ldp.interface.add", r#"{"interface":"ether1"}"#.into()),
        // bfdd's own peer (its session goes to the daemon's engine, the
        // data plane). Not OSPF's `bfd`: proto-ospf does not type it into
        // ospfd yet (G3.6l).
        (
            "routing.bfd.peer.add",
            format!(r#"{{"address":"10.0.12.{other}","interface":"ether1"}}"#),
        ),
    ];
    for (cmd, params) in &steps {
        vm.ok(log, cmd, params)?;
    }
    Ok(())
}

/// What router `n` must read back from FRR once the other one is up.
fn verify(
    vm: &mut Vm,
    log: &mut std::fs::File,
    nums: &mut Numbers,
    n: u8,
    frr: Option<&str>,
    t0: Instant,
) -> Result<(), String> {
    let other = 3 - n;
    let peer_lo = format!("10.255.0.{other}/32");
    let r = format!("r{n}");

    let version = sh(vm, log, "/usr/sbin/zebra --version | head -n 1")?;
    nums.put(&format!("{r}: FRR"), version.clone());
    if let Some(want) = frr {
        check(
            version.contains(&format!("version {want}")),
            format!("{r}: zebra reports '{version}', the image pins FRR {want}"),
        )?;
    }

    // The link first: OSPF over it is what is under test, not QEMU.
    let deadline = Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let p = sh(
            vm,
            log,
            &format!("ping -c 1 -W 1 10.0.12.{other} | tail -n 1"),
        )?;
        if p.contains("min/avg/max") {
            break;
        }
        if Instant::now() >= deadline {
            let a = sh(vm, log, "{ ip addr show ether1; ip route; }")?;
            let i = vm.run(log, "interface.list", "{}")?;
            let ad = vm.run(log, "ip.address.list", "{}")?;
            eprintln!("   [{r}] interfaces: {i}\n   [{r}] addresses: {ad}");
            return Err(format!("{r}: no link to 10.0.12.{other}: {p}; {a}"));
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    let nb = until(vm, log, 90, "routing.ospf.neighbor.list", "{}", |v| {
        v["result"]["rows"]
            .as_array()
            .is_some_and(|a| a.iter().any(|x| x["state"] == "Full"))
    })?;
    nums.put(
        &format!("{r}: OSPF neighbor (ospfd)"),
        format!(
            "{} {} at +{:.1} s",
            nb["result"]["rows"][0]["router_id"],
            nb["result"]["rows"][0]["label"],
            t0.elapsed().as_secs_f64()
        ),
    );

    let sr = until(
        vm,
        log,
        60,
        "routing.ospf.segment-routing.database",
        "{}",
        |v| {
            v["result"]["sids"].as_array().is_some_and(|a| {
                a.iter()
                    .any(|s| s["prefix"] == peer_lo.as_str() && !s["out_label"].is_null())
            })
        },
    )?;
    let sid = sr["result"]["sids"]
        .as_array()
        .and_then(|a| a.iter().find(|s| s["prefix"] == peer_lo.as_str()))
        .cloned()
        .unwrap_or(Value::Null);
    nums.put(
        &format!("{r}: SR prefix SID of {peer_lo} (ospfd)"),
        format!(
            "index {} label {} in {} out {} ({} nodes)",
            sid["index"],
            sid["label"],
            sid["in_label"],
            sid["out_label"],
            sr["result"]["nodes"].as_array().map_or(0, Vec::len)
        ),
    );

    let ldp = until(vm, log, 60, "mpls.ldp.neighbor.list", "{}", |v| {
        v["result"]
            .as_array()
            .is_some_and(|a| a.iter().any(|x| x["operational"] == true))
    })?;
    nums.put(
        &format!("{r}: LDP neighbor (ldpd)"),
        format!(
            "{} {} at +{:.1} s",
            ldp["result"][0]["lsr_id"],
            ldp["result"][0]["state"],
            t0.elapsed().as_secs_f64()
        ),
    );

    let ft = until(vm, log, 60, "mpls.forwarding-table.page", "{}", |v| {
        v["result"]["summary"]["labels"].as_u64().unwrap_or(0) > 0
    })?;
    nums.put(
        &format!("{r}: MPLS forwarding table"),
        format!(
            "{} rows, {} labeled, {} kernel labels",
            ft["result"]["summary"]["rows"],
            ft["result"]["summary"]["labeled"],
            ft["result"]["summary"]["labels"]
        ),
    );

    let ping = sh(
        vm,
        log,
        &format!("ping -c 3 -W 2 10.255.0.{other} | tail -n 2"),
    )?;
    check(
        ping.contains(" 0% packet loss"),
        format!("{r}: ping 10.255.0.{other}: {ping}"),
    )?;
    nums.put(&format!("{r}: ping of the other loopback"), ping);

    let rss = sh(
        vm,
        log,
        &format!(
            "for p in {DAEMONS} corerouter-daemon; do pidof -s $p >/dev/null && printf '%s=%s ' $p $(grep VmRSS /proc/$(pidof -s $p)/status | tr -s ' ' | cut -d' ' -f2); done"
        ),
    )?;
    nums.put(&format!("{r}: RSS KiB (OSPF+SR+LDP up)"), rss);
    let mem = sh(
        vm,
        log,
        "grep -E 'MemTotal|MemAvailable' /proc/meminfo | tr -s ' '",
    )?;
    nums.put(&format!("{r}: memory"), mem);
    let bfd = until(vm, log, 60, "routing.bfd.session.list", "{}", |v| {
        v["result"]["sessions"]
            .as_array()
            .is_some_and(|a| a.iter().any(|s| s["state"] == "up"))
    })?;
    let s = &bfd["result"]["sessions"][0];
    nums.put(
        &format!("{r}: BFD session"),
        format!(
            "{} {} (users {}, tx {} µs, detect {} µs)",
            s["peer"], s["state"], s["users"], s["tx_interval_us"], s["detect_time_us"]
        ),
    );

    Ok(())
}

pub fn frr_test(root: &Path, images: &Path, args: &[String]) -> Result<(), String> {
    let mut tcg = false;
    for a in args {
        match a.as_str() {
            "--tcg" => tcg = true,
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    for f in ["disk.img", "bzImage"] {
        check(
            images.join(f).exists(),
            format!(
                "{} missing: run `cargo xtask os build` first",
                images.join(f).display()
            ),
        )?;
    }
    let frr = pinned_frr(&root.join("os"))?;
    let work = root.join("os/out/frr-test");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let log_path = work.join("console.log");
    let mut log = std::fs::File::create(&log_path).map_err(|e| e.to_string())?;
    let kvm = !tcg && super::kvm_usable();
    eprintln!(
        "frr-test ({}), console → {}",
        if kvm { "KVM" } else { "TCG" },
        log_path.display()
    );
    let started = Instant::now();
    let mut nums = Numbers(Vec::new());
    let ports = (udp_port()?, udp_port()?);
    let mut r1 = boot(&work, images, kvm, &mut log, 1, ports)?;
    let mut r2 = boot(&work, images, kvm, &mut log, 2, ports)?;
    for (vm, n) in [(&mut r1, 1), (&mut r2, 2)] {
        let r = vm.expect_all(&mut log, &["ready:", "maintenance shell", "FRR up:"], 120)?;
        nums.put(
            &format!("r{n}: kernel → daemon ready"),
            ready_s(r.first().map_or("", String::as_str)),
        );
        nums.put(
            &format!("r{n}: FRR"),
            r.get(2)
                .and_then(|l| l.split("FRR up: ").nth(1))
                .unwrap_or("?")
                .to_owned(),
        );
    }
    // FRR is attached before the configuration reaches it.
    for vm in [&mut r1, &mut r2] {
        until(
            vm,
            &mut log,
            30,
            "system.service.print",
            r#"{"name":"frr"}"#,
            |v| v["result"][0]["state"] == "running",
        )?;
    }
    for (vm, n) in [(&mut r1, 1), (&mut r2, 2)] {
        let idle = on_demand_running(vm, &mut log)?;
        check(
            idle.is_empty(),
            format!("r{n}: on-demand FRR daemons before any configuration: {idle}"),
        )?;
        nums.put(
            &format!("r{n}: on-demand FRR daemons at boot"),
            "none".to_owned(),
        );
    }
    let t0 = Instant::now();
    configure(&mut r1, &mut log, 1)?;
    configure(&mut r2, &mut log, 2)?;
    nums.put(
        "both routers configured (13 commands each)",
        format!("{:.1} s", t0.elapsed().as_secs_f64()),
    );
    let res = verify(&mut r1, &mut log, &mut nums, 1, frr.as_deref(), t0)
        .and_then(|()| verify(&mut r2, &mut log, &mut nums, 2, frr.as_deref(), t0))
        .and_then(|()| on_demand(&mut r1, &mut log, &mut nums));
    if let Err(e) = res {
        for (vm, n) in [(&mut r1, 1), (&mut r2, 2)] {
            let diag = sh(
                vm,
                &mut log,
                "{ ip route; tail -n 15 /var/log/frr-ospfd.log /var/log/frr-ldpd.log /var/log/frr-bfdd.log; grep -iE 'frr|ospf|ldp|bfd' /var/log/corerouter-daemon.log | tail -n 15; }",
            )
            .unwrap_or_default();
            let dbg = sh(vm, &mut log, "{ ls /var/run/frr; grep -iE 'dplane|bfdd' /var/log/corerouter-daemon.log | grep -v 'command(s) applied\\|differently' | tail -n 8; }").unwrap_or_default();
            let nb = vm
                .run(&mut log, "routing.ospf.neighbor.list", "{}")
                .unwrap_or_default();
            let oi = vm
                .run(&mut log, "routing.ospf.interface.list", "{}")
                .unwrap_or_default();
            eprintln!("   [r{n}] DBG {dbg}\n   [r{n}] NB {nb}\n   [r{n}] OI {oi}");
            let bfd = vm
                .run(&mut log, "system.service.print", r#"{"name":"bfd"}"#)
                .map(|v| v["result"][0].to_string())
                .unwrap_or_default();
            eprintln!("   [r{n}] {diag}\n   [r{n}] bfd service: {bfd}");
        }
        return Err(e);
    }
    r1.poweroff(&mut log)?;
    r2.poweroff(&mut log)?;
    eprintln!(
        "\nfrr-test ok in {:.1} s ({}):",
        started.elapsed().as_secs_f64(),
        if kvm { "KVM" } else { "TCG" }
    );
    for (k, v) in &nums.0 {
        eprintln!("  {k}: {v}");
    }
    for n in [1, 2] {
        let _ = std::fs::remove_file(work.join(format!("r{n}.qcow2")));
    }
    Ok(())
}

/// A free UDP port on the loopback (bound, then released for QEMU).
fn udp_port() -> Result<u16, String> {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .map(|a| a.port())
        .map_err(|e| format!("udp port: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pinned_version_comes_from_the_patch() {
        let os = Path::new(env!("CARGO_MANIFEST_DIR")).join("../os");
        assert_eq!(pinned_frr(&os).unwrap().as_deref(), Some("10.7.1"));
    }
}

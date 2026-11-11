//! G1.26i: `cargo xtask os forward-test` — an image nobody tuned routes, in
//! QEMU as the user (no root, no tap):
//!
//! ```text
//!   a.ether1 ───────── r.ether1   r.ether2 ───────── b.ether1
//!   10.26.1.2/24       10.26.1.1  10.26.2.1          10.26.2.2/24
//!   2001:db8:26:1::2   …:1::1     …:2::1             2001:db8:26:2::2
//! ```
//!
//! - three guests of `disk.img` (throw-away qcow2 overlays), booted the
//!   factory way with the maintenance shell on the serial console; each
//!   link is a QEMU UDP socket pair on the host's loopback;
//! - `r` gets addresses and nothing else: its kernel must already forward
//!   IPv4 and IPv6 (`/proc/sys`), with no `system.tuning` entry and no
//!   forwarding finding, and `a` must reach `b` through it both ways of
//!   addressing, one hop away (TTL 63);
//! - the operator's `net.ipv4.ip_forward = 0` on `r` stops IPv4 (and only
//!   IPv4) and brings the critical finding; `unset` routes again;
//! - the live ISO (`corerouter-install.iso`), over TLS as the first
//!   operator: forwarding on, a kernel parameter accepted at run time, a
//!   port setting refused.

#![allow(clippy::indexing_slicing)]

use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use serde_json::Value;

use super::ab::{Numbers, Vm, check, fresh_vars, qemu_base, ready_s, start};
use super::install::sh;

const FWD4: &str = "net.ipv4.ip_forward";
const FWD6: &str = "net.ipv6.conf.all.forwarding";

/// One end of a link: (this side's UDP port, the other side's, the MAC).
type Link = (u16, u16, &'static str);

/// A guest of `disk.img` with one NIC per link, in order (`ether1`, …).
fn boot(
    work: &Path,
    images: &Path,
    kvm: bool,
    log: &mut std::fs::File,
    name: &str,
    links: &[Link],
) -> Result<Vm, String> {
    let disk = work.join(format!("{name}.qcow2"));
    let _ = std::fs::remove_file(&disk);
    let st = Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2", "-F", "raw", "-b"])
        .arg(images.join("disk.img"))
        .arg(&disk)
        .status()
        .map_err(|e| format!("qemu-img: {e}"))?;
    check(st.success(), "qemu-img create failed")?;
    let vars = work.join(format!("{name}-vars.fd"));
    fresh_vars(&vars)?;
    let mut cmd = qemu_base(kvm, &vars);
    cmd.arg("-drive")
        .arg(format!("file={},if=virtio,format=qcow2", disk.display()));
    for (i, (local, remote, mac)) in links.iter().enumerate() {
        cmd.arg("-netdev").arg(format!(
            "socket,id=l{i},udp=127.0.0.1:{remote},localaddr=127.0.0.1:{local}"
        ));
        // A slot of its own: `ether1` is the first link, whatever QEMU
        // would pick.
        cmd.arg("-device").arg(format!(
            "virtio-net-pci,netdev=l{i},mac={mac},bus=pcie.0,addr=0x{:x}",
            0x10 + i
        ));
    }
    // The factory boot (as frr-test's), with the maintenance shell.
    cmd.arg("-kernel").arg(images.join("bzImage"));
    cmd.arg("-append").arg("corerouter.shell=ttyS0");
    start(log, name, cmd)
}

fn udp_port() -> Result<u16, String> {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .and_then(|s| s.local_addr())
        .map(|a| a.port())
        .map_err(|e| format!("udp port: {e}"))
}

/// `/proc/sys/<path>` of the guest.
fn sysctl(vm: &mut Vm, log: &mut std::fs::File, path: &str) -> Result<String, String> {
    sh(vm, log, &format!("cat /proc/sys/{path}"))
}

/// The forwarding findings of `system.tuning.diagnose`.
fn forwarding_findings(vm: &mut Vm, log: &mut std::fs::File) -> Result<Vec<String>, String> {
    let d = vm.ok(log, "system.tuning.diagnose", "{}")?;
    Ok(d["findings"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|f| {
                    let id = f["id"].as_str()?;
                    id.starts_with("forwarding")
                        .then(|| format!("{}:{id}", f["severity"].as_str().unwrap_or("")))
                })
                .collect()
        })
        .unwrap_or_default())
}

/// One round of pings to `to` from the guest: `(all answered, none
/// answered, what it printed)`. IPv4 by the shell's ping (it shows the
/// TTL); IPv6 by the daemon's own (`tool.ping.start`: the image's BusyBox
/// ping has no IPv6).
fn ping_round(
    vm: &mut Vm,
    log: &mut std::fs::File,
    to: &str,
) -> Result<(bool, bool, String), String> {
    if !to.contains(':') {
        let out = sh(vm, log, &format!("ping -c 3 -W 2 {to}"))?;
        return Ok((
            out.contains(" 0% packet loss"),
            out.contains("100% packet loss"),
            out,
        ));
    }
    let task = vm.ok(
        log,
        "tool.ping.start",
        &format!(r#"{{"address":"{to}","count":3,"interval_ms":300,"timeout_ms":1500}}"#),
    )?;
    let id = task["task_id"]
        .as_u64()
        .ok_or("tool.ping.start: no task_id")?;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let p = vm.ok(log, "tool.task.poll", &format!(r#"{{"id":{id}}}"#))?;
        if p["done"] == true {
            let t = &p["summary"]["targets"][0];
            let (sent, got) = (t["sent"].as_u64(), t["received"].as_u64());
            return Ok((
                sent == Some(3) && got == Some(3),
                got == Some(0),
                format!(
                    "{} sent, {} received, {}% loss, avg {} ms",
                    t["sent"], t["received"], t["loss_pct"], t["avg_ms"]
                ),
            ));
        }
        check(
            Instant::now() < deadline,
            format!("ping {to}: never done: {p}"),
        )?;
        std::thread::sleep(Duration::from_millis(400));
    }
}

/// Ping `to` from the guest until every answer of a round comes (`want`)
/// or, for `!want`, one round with none; the last output.
fn ping(vm: &mut Vm, log: &mut std::fs::File, to: &str, want: bool) -> Result<String, String> {
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        let (all, none, out) = ping_round(vm, log, to)?;
        if (want && all) || (!want && none) {
            return Ok(out);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "ping {to}: expected {}: {out}",
                if want { "answers" } else { "no answer" }
            ));
        }
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// An end host: its port, addresses and default routes through `r`.
fn host(vm: &mut Vm, log: &mut std::fs::File, net: u8) -> Result<(), String> {
    for (cmd, params) in [
        (
            "interface.set",
            r#"{"name":"ether1","disabled":false}"#.to_owned(),
        ),
        (
            "ip.address.add",
            format!(r#"{{"address":"10.26.{net}.2/24","interface":"ether1"}}"#),
        ),
        (
            "ip.address.add",
            format!(r#"{{"address":"2001:db8:26:{net}::2/64","interface":"ether1"}}"#),
        ),
        (
            "ip.route.add",
            format!(r#"{{"dst_address":"0.0.0.0/0","gateway":"10.26.{net}.1"}}"#),
        ),
        (
            "ip.route.add",
            format!(r#"{{"dst_address":"::/0","gateway":"2001:db8:26:{net}::1"}}"#),
        ),
    ] {
        vm.ok(log, cmd, &params)?;
    }
    Ok(())
}

fn installed(
    work: &Path,
    images: &Path,
    kvm: bool,
    log: &mut std::fs::File,
    nums: &mut Numbers,
) -> Result<(), String> {
    let (a_r, r_a, r_b, b_r) = (udp_port()?, udp_port()?, udp_port()?, udp_port()?);
    let mut a = boot(
        work,
        images,
        kvm,
        log,
        "a",
        &[(a_r, r_a, "52:54:00:26:01:02")],
    )?;
    let mut r = boot(
        work,
        images,
        kvm,
        log,
        "r",
        &[
            (r_a, a_r, "52:54:00:26:01:01"),
            (r_b, b_r, "52:54:00:26:02:01"),
        ],
    )?;
    let mut b = boot(
        work,
        images,
        kvm,
        log,
        "b",
        &[(b_r, r_b, "52:54:00:26:02:02")],
    )?;
    for (vm, n) in [(&mut a, "a"), (&mut r, "r"), (&mut b, "b")] {
        let got = vm.expect_all(log, &["ready:", "maintenance shell"], 120)?;
        nums.put(
            &format!("{n}: kernel → daemon ready"),
            ready_s(got.first().map_or("", String::as_str)),
        );
    }

    // Nobody configured anything: the router already forwards.
    let fwd = (
        sysctl(&mut r, log, "net/ipv4/ip_forward")?,
        sysctl(&mut r, log, "net/ipv6/conf/all/forwarding")?,
    );
    check(
        fwd == ("1".to_owned(), "1".to_owned()),
        format!("r: ip_forward and ipv6 forwarding at boot: {fwd:?}"),
    )?;
    nums.put(
        "r: ip_forward / ipv6 all.forwarding at boot, no config",
        "1 / 1",
    );
    let set = r.ok(log, "system.tuning.print", "{}")?;
    check(
        set == Value::Array(Vec::new()),
        format!("r: system.tuning is not empty: {set}"),
    )?;
    let found = forwarding_findings(&mut r, log)?;
    check(found.is_empty(), format!("r: findings at boot: {found:?}"))?;
    nums.put(
        "r: kernel release",
        sysctl(&mut r, log, "kernel/osrelease")?,
    );
    // What the forwarding change leaves (`inet_forward_change`,
    // `addrconf_fixup_forwarding`), for the record.
    for (label, path) in [
        (
            "ipv4 conf/all/accept_redirects",
            "net/ipv4/conf/all/accept_redirects",
        ),
        (
            "ipv4 conf/all/send_redirects",
            "net/ipv4/conf/all/send_redirects",
        ),
        ("ipv4 conf/all/rp_filter", "net/ipv4/conf/all/rp_filter"),
        (
            "ipv4 conf/default/forwarding",
            "net/ipv4/conf/default/forwarding",
        ),
        (
            "ipv6 conf/default/forwarding",
            "net/ipv6/conf/default/forwarding",
        ),
        ("ipv6 conf/all/accept_ra", "net/ipv6/conf/all/accept_ra"),
    ] {
        let v = sysctl(&mut r, log, path)?;
        nums.put(&format!("r: {label}"), v);
    }
    let diff = r.ok(
        log,
        "system.tuning.profile.diff",
        r#"{"profile":"balanced"}"#,
    )?;
    let names: Vec<&str> = diff
        .as_array()
        .map(|a| a.iter().filter_map(|d| d["name"].as_str()).collect())
        .unwrap_or_default();
    check(
        !names.iter().any(|n| *n == FWD4 || *n == FWD6),
        format!("the balanced profile still wants forwarding: {names:?}"),
    )?;
    nums.put(
        &format!("r: balanced would change {} parameters", names.len()),
        names.join(" "),
    );

    for (cmd, params) in [
        ("interface.set", r#"{"name":"ether1","disabled":false}"#),
        ("interface.set", r#"{"name":"ether2","disabled":false}"#),
        (
            "ip.address.add",
            r#"{"address":"10.26.1.1/24","interface":"ether1"}"#,
        ),
        (
            "ip.address.add",
            r#"{"address":"10.26.2.1/24","interface":"ether2"}"#,
        ),
        (
            "ip.address.add",
            r#"{"address":"2001:db8:26:1::1/64","interface":"ether1"}"#,
        ),
        (
            "ip.address.add",
            r#"{"address":"2001:db8:26:2::1/64","interface":"ether2"}"#,
        ),
    ] {
        r.ok(log, cmd, params)?;
    }
    host(&mut a, log, 1)?;
    host(&mut b, log, 2)?;
    // Addresses alone: still nothing of tuning in the config.
    let set = r.ok(log, "system.tuning.print", "{}")?;
    check(set == Value::Array(Vec::new()), format!("r: {set}"))?;

    let t0 = Instant::now();
    let v4 = ping(&mut a, log, "10.26.2.2", true)?;
    check(
        v4.contains("ttl=63"),
        format!("a → b was not routed one hop away: {v4}"),
    )?;
    nums.put("a → b through r, IPv4", v4);
    let v6 = ping(&mut a, log, "2001:db8:26:2::2", true)?;
    nums.put("a → b through r, IPv6", v6);
    let back = ping(&mut b, log, "10.26.1.2", true)?;
    nums.put("b → a through r, IPv4", back);
    nums.put(
        "first routed answers after the addresses",
        format!("{:.1} s", t0.elapsed().as_secs_f64()),
    );
    for iface in ["ether1", "ether2"] {
        let v = sysctl(&mut r, log, &format!("net/ipv6/conf/{iface}/accept_ra"))?;
        check(
            v == "0",
            format!("r: accept_ra of {iface} is {v} (auto, no DHCPv6 client: 0)"),
        )?;
    }

    // The operator's 0: IPv4 stops, IPv6 goes on, the finding is critical.
    r.ok(
        log,
        "system.tuning.set",
        &format!(r#"{{"name":"{FWD4}","value":0}}"#),
    )?;
    let now = sysctl(&mut r, log, "net/ipv4/ip_forward")?;
    check(now == "0", format!("r: ip_forward after set 0: {now}"))?;
    let off = ping(&mut a, log, "10.26.2.2", false)?;
    nums.put("a → b with ip_forward = 0 on r", off);
    ping(&mut a, log, "2001:db8:26:2::2", true)?;
    let found = forwarding_findings(&mut r, log)?;
    check(
        found == ["critical:forwarding_off"],
        format!("r: findings with ip_forward = 0: {found:?}"),
    )?;
    // Taken out: CoreRouter's default again.
    r.ok(
        log,
        "system.tuning.unset",
        &format!(r#"{{"name":"{FWD4}"}}"#),
    )?;
    let now = sysctl(&mut r, log, "net/ipv4/ip_forward")?;
    check(now == "1", format!("r: ip_forward after unset: {now}"))?;
    ping(&mut a, log, "10.26.2.2", true)?;
    nums.put("a → b after unset", "routed again");

    a.poweroff(log)?;
    b.poweroff(log)?;
    r.poweroff(log)?;
    for n in ["a", "r", "b"] {
        let _ = std::fs::remove_file(work.join(format!("{n}.qcow2")));
    }
    Ok(())
}

/// `corerouter-cli run` on the live guest over TLS, as the first operator
/// (`admin` without a password, the certificate accepted on first use).
fn live_cli(work: &Path, cli: &Path, port: u16, id: &str, params: &str) -> Result<Value, String> {
    let home = work.join("live-home");
    std::fs::create_dir_all(&home).map_err(|e| e.to_string())?;
    let out = Command::new(cli)
        .args([
            "--connect",
            &format!("tls://127.0.0.1:{port}"),
            "--user",
            "admin",
            "--accept-new-cert",
            "run",
            id,
            params,
        ])
        .env("HOME", &home)
        .env("COREROUTER_KNOWN_HOSTS", home.join("known_hosts"))
        .env("COREROUTER_PASSWORD", "")
        .env("RUST_LOG", "off")
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("{}: {e}", cli.display()))?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    if !out.status.success() {
        return Err(format!("{text}{}", String::from_utf8_lossy(&out.stderr)));
    }
    serde_json::from_str(&text).map_err(|e| format!("{id}: {e}: {text}"))
}

/// The live ISO: the same daemon with `--live`, the root in RAM.
fn live(
    root: &Path,
    work: &Path,
    images: &Path,
    kvm: bool,
    log: &mut std::fs::File,
    nums: &mut Numbers,
) -> Result<(), String> {
    let cli = super::push::cli(root)?;
    let vars = work.join("live-vars.fd");
    fresh_vars(&vars)?;
    let port = super::free_port()?;
    let mut cmd = qemu_base(kvm, &vars);
    cmd.arg("-drive").arg(format!(
        "file={},if=none,id=cd,format=raw,media=cdrom,readonly=on",
        images.join("corerouter-install.iso").display()
    ));
    cmd.args(["-device", "ide-cd,drive=cd,bootindex=0"]);
    cmd.arg("-netdev").arg(format!(
        "user,id=n0,hostfwd=tcp:127.0.0.1:{port}-:{}",
        super::GUEST_TLS_PORT
    ));
    cmd.args(["-device", "virtio-net-pci,netdev=n0"]);
    let mut vm = start(log, "live", cmd)?;
    vm.expect_all(
        log,
        &["/config: tmpfs (live image", "ready:", "NOT INSTALLED"],
        180,
    )?;
    let deadline = Instant::now() + Duration::from_secs(90);
    let print = loop {
        match live_cli(
            work,
            &cli,
            port,
            "system.tuning.parameter.print",
            r#"{"tab":"kernel"}"#,
        ) {
            Ok(v) => break v,
            Err(e) => {
                check(
                    Instant::now() < deadline,
                    format!("live: no answer over TLS: {e}"),
                )?;
                std::thread::sleep(Duration::from_millis(700));
            }
        }
    };
    let row = |name: &str| {
        print["params"]
            .as_array()
            .and_then(|a| a.iter().find(|p| p["name"] == name))
            .cloned()
            .unwrap_or(Value::Null)
    };
    for name in [FWD4, FWD6] {
        let p = row(name);
        check(
            p["current"] == 1 && p["configured"].is_null() && p["router_default"] == 1,
            format!("live: {name}: {p}"),
        )?;
    }
    nums.put("live: ip_forward / ipv6 all.forwarding (kernel)", "1 / 1");
    let d = live_cli(work, &cli, port, "system.tuning.diagnose", "{}")?;
    check(
        !d.to_string().contains("forwarding"),
        format!("live: a forwarding finding: {d}"),
    )?;
    // A kernel parameter at run time (nothing is kept: no disk)…
    live_cli(
        work,
        &cli,
        port,
        "system.tuning.set",
        r#"{"name":"net.core.netdev_budget","value":600}"#,
    )?;
    let after = live_cli(
        work,
        &cli,
        port,
        "system.tuning.parameter.print",
        r#"{"tab":"kernel"}"#,
    )?;
    let budget = after["params"]
        .as_array()
        .and_then(|a| a.iter().find(|p| p["name"] == "net.core.netdev_budget"))
        .map(|p| p["current"].clone())
        .unwrap_or(Value::Null);
    check(budget == 600, format!("live: netdev_budget is {budget}"))?;
    // … and a port's setting still refused.
    let e = live_cli(
        work,
        &cli,
        port,
        "system.tuning.interface.set",
        r#"{"name":"ether1","key":"txqueuelen","value":2000}"#,
    )
    .err()
    .unwrap_or_default();
    check(
        e.contains("live image"),
        format!("live: a port setting was not refused: {e}"),
    )?;
    nums.put(
        "live: system.tuning.set accepted, interface.set refused",
        "ok",
    );
    drop(vm);
    Ok(())
}

pub fn forward_test(root: &Path, images: &Path, args: &[String]) -> Result<(), String> {
    let (mut tcg, mut with_live) = (false, true);
    for a in args {
        match a.as_str() {
            "--tcg" => tcg = true,
            "--no-live" => with_live = false,
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
    let work = super::out_dir(root)?.join("forward-test");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let log_path = work.join("console.log");
    let mut log = std::fs::File::create(&log_path).map_err(|e| e.to_string())?;
    let kvm = !tcg && super::kvm_usable();
    eprintln!(
        "forward-test ({}), console → {}",
        if kvm { "KVM" } else { "TCG" },
        log_path.display()
    );
    let started = Instant::now();
    let mut nums = Numbers(Vec::new());
    installed(&work, images, kvm, &mut log, &mut nums)?;
    if with_live {
        live(root, &work, images, kvm, &mut log, &mut nums)?;
    }
    eprintln!(
        "\nforward-test ok in {:.1} s ({}):",
        started.elapsed().as_secs_f64(),
        if kvm { "KVM" } else { "TCG" }
    );
    for (k, v) in &nums.0 {
        eprintln!("  {k}: {v}");
    }
    Ok(())
}

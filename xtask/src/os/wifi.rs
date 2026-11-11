//! G1.30: `cargo xtask os wifi-test` — the image as a Wi-Fi station, end to
//! end, in QEMU as the user (no root, no card):
//!
//! - the built `disk.img` boots the factory way with the maintenance shell,
//!   two of the kernel's simulated radios (`corerouter.hwsim=2`,
//!   `mac80211_hwsim`: real cfg80211 and mac80211, frames between the radios
//!   in software) and the first of them kept out of the router's hands
//!   (`corerouter.unmanaged=wifi1`);
//! - on that first radio `hostapd` runs an access point with WPA2 and WPA3
//!   (transition mode). hostapd is not in the image: the build leaves it in
//!   `images/test-tools/`, and the test hands it to the guest on a small
//!   read-only disk;
//! - the router's own radio (`wifi2`) is driven only through commands
//!   (`corerouter-init run`, the same `Session::execute` as the CLI and MCP):
//!   the country, a scan that must hear the access point, the network with
//!   its passphrase, a wrong passphrase, WPA2 and WPA3 forced, a network
//!   that is not there, the access point going away and coming back;
//! - what must follow is read back from the router (`interface.wifi.monitor`)
//!   and from the kernel (an echo across the encrypted link, the regulatory
//!   domain, no line about `regulatory.db`).
//!
//! What it cannot show: a card. Firmware loading, a driver's quirks and the
//! airplane-mode key are the notebook's.

#![allow(clippy::indexing_slicing)]

use std::path::Path;
use std::process::Command;
use std::time::Instant;

use serde_json::Value;

use super::ab::{Numbers, Vm, check, fresh_vars, qemu_base, ready_s, start};
use super::install::{sh, until};

const SSID: &str = "CoreRouter-Teste";
/// A test value, on a disposable VM.
const PASSPHRASE: &str = "senha-de-teste-wifi";
/// The radios `mac80211_hwsim` makes: `02:00:00:00:<n>:00`.
const AP_BSSID: &str = "02:00:00:00:00:00";
const TOOLS: &str = "/tmp/tt";

/// The access point's configuration: 2.4 GHz channel 1 (allowed in every
/// domain), WPA2 and WPA3 with one passphrase, management frame protection
/// offered, both ways of deriving the SAE element.
fn hostapd_conf() -> String {
    format!(
        "interface=wifi1\ndriver=nl80211\nssid={SSID}\nhw_mode=g\nchannel=1\nieee80211n=1\n\
         wpa=2\nwpa_key_mgmt=WPA-PSK SAE\nrsn_pairwise=CCMP\nwpa_passphrase={PASSPHRASE}\n\
         ieee80211w=1\nsae_pwe=2\n"
    )
}

/// A small ext4 image with hostapd and its configuration (`mke2fs -d`, the
/// build's own: no root, no loop device).
fn tools_disk(images: &Path, work: &Path) -> Result<std::path::PathBuf, String> {
    let hostapd = images.join("test-tools/hostapd");
    check(
        hostapd.is_file(),
        format!(
            "{} missing: run `cargo xtask os build` (it builds the test's access point)",
            hostapd.display()
        ),
    )?;
    let dir = work.join("tools");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    std::fs::copy(&hostapd, dir.join("hostapd")).map_err(|e| format!("hostapd: {e}"))?;
    std::fs::write(dir.join("ap.conf"), hostapd_conf()).map_err(|e| e.to_string())?;
    let img = work.join("tools.img");
    let _ = std::fs::remove_file(&img);
    let mke2fs = images
        .parent()
        .map(|b| b.join("host/sbin/mke2fs"))
        .filter(|p| p.is_file())
        .ok_or("the build's mke2fs (host/sbin/mke2fs) is missing")?;
    let out = Command::new(mke2fs)
        .args(["-q", "-t", "ext4", "-d"])
        .arg(&dir)
        .arg(&img)
        .arg("16M")
        .output()
        .map_err(|e| format!("mke2fs: {e}"))?;
    check(
        out.status.success(),
        format!("mke2fs: {}", String::from_utf8_lossy(&out.stderr)),
    )?;
    Ok(img)
}

fn boot(
    work: &Path,
    images: &Path,
    tools: &Path,
    kvm: bool,
    log: &mut std::fs::File,
) -> Result<Vm, String> {
    let disk = work.join("r.qcow2");
    let _ = std::fs::remove_file(&disk);
    let st = Command::new("qemu-img")
        .args(["create", "-q", "-f", "qcow2", "-F", "raw", "-b"])
        .arg(images.join("disk.img"))
        .arg(&disk)
        .status()
        .map_err(|e| format!("qemu-img: {e}"))?;
    check(st.success(), "qemu-img create failed")?;
    let vars = work.join("vars.fd");
    fresh_vars(&vars)?;
    let mut cmd = qemu_base(kvm, &vars);
    cmd.arg("-drive")
        .arg(format!("file={},if=virtio,format=qcow2", disk.display()));
    cmd.arg("-drive").arg(format!(
        "file={},if=virtio,format=raw,readonly=on",
        tools.display()
    ));
    cmd.args([
        "-netdev",
        "user,id=n0",
        "-device",
        "virtio-net-pci,netdev=n0",
    ]);
    cmd.arg("-kernel").arg(images.join("bzImage"));
    cmd.arg("-append")
        .arg("corerouter.shell=ttyS0 corerouter.hwsim=2 corerouter.unmanaged=wifi1");
    start(log, "r", cmd)
}

fn monitor(
    vm: &mut Vm,
    log: &mut std::fs::File,
    secs: u64,
    pred: impl Fn(&Value) -> bool,
) -> Result<Value, String> {
    until(
        vm,
        log,
        secs,
        "interface.wifi.monitor",
        r#"{"name":"wifi2"}"#,
        |v| pred(&v["result"]),
    )
    .map(|v| v["result"].clone())
}

fn set(vm: &mut Vm, log: &mut std::fs::File, params: &Value) -> Result<Value, String> {
    vm.ok(log, "interface.wifi.set", &params.to_string())
}

fn start_ap(vm: &mut Vm, log: &mut std::fs::File) -> Result<(), String> {
    let out = sh(
        vm,
        log,
        &format!(
            "{{ {TOOLS}/hostapd -B {TOOLS}/ap.conf; sleep 1; pidof hostapd >/dev/null && echo AP-UP; }}"
        ),
    )?;
    check(
        out.contains("AP-UP"),
        format!("hostapd did not start: {out}"),
    )
}

fn run(vm: &mut Vm, log: &mut std::fs::File, nums: &mut Numbers) -> Result<(), String> {
    // The radios: named, the access point's left alone, the router's
    // adopted as what it is, off.
    until(vm, log, 30, "interface.wifi.list", "{}", |v| {
        v["result"]
            .as_array()
            .is_some_and(|a| a.len() == 1 && a[0]["name"] == "wifi2" && a[0]["state"] == "disabled")
    })?;
    let all = vm.ok(log, "interface.list", "{}")?;
    let ap = all
        .as_array()
        .and_then(|a| a.iter().find(|i| i["name"] == "wifi1"))
        .cloned()
        .unwrap_or(Value::Null);
    check(
        ap["managed"] == false
            && ap["unmanaged_reason"]
                .as_str()
                .is_some_and(|r| r.contains("--unmanaged")),
        format!("wifi1 must be left alone: {ap}"),
    )?;
    nums.put(
        "radios",
        "wifi1 (the test's access point, unmanaged), wifi2 (adopted, off)",
    );

    // The access point, from the tools disk.
    let out = sh(
        vm,
        log,
        &format!("{{ mkdir -p {TOOLS} && mount -t ext4 -o ro /dev/vdb {TOOLS} && ls {TOOLS}; }}"),
    )?;
    check(out.contains("hostapd"), format!("tools disk: {out}"))?;
    start_ap(vm, log)?;
    // No country, no radio.
    let e = vm.run(log, "interface.wifi.enable", r#"{"name":"wifi2"}"#)?;
    check(
        e["ok"] == false && e.to_string().contains("interface.wifi.country.set"),
        format!("enabling without a country: {e}"),
    )?;
    vm.ok(log, "interface.wifi.country.set", r#"{"country":"BR"}"#)?;
    vm.ok(log, "interface.wifi.enable", r#"{"name":"wifi2"}"#)?;
    monitor(vm, log, 20, |m| m["state"] == "idle")?;
    let reg = until(vm, log, 20, "interface.wifi.country.get", "{}", |v| {
        v["result"]["in_force"] == "BR"
    })?;
    check(
        reg["result"]["error"].is_null(),
        format!("the regulatory domain: {reg}"),
    )?;
    let db = sh(vm, log, "dmesg | grep -c 'regulatory.db'")?;
    check(
        db.trim() == "0",
        format!("the kernel complained about regulatory.db ({db} lines)"),
    )?;
    nums.put(
        "regulatory domain",
        "BR in force (the kernel's signed database loaded)",
    );

    // The scan hears the access point.
    let t = Instant::now();
    vm.ok(log, "interface.wifi.scan", r#"{"name":"wifi2"}"#)?;
    let seen = until(
        vm,
        log,
        30,
        "interface.wifi.networks",
        r#"{"name":"wifi2"}"#,
        |v| {
            v["result"]["networks"]
                .as_array()
                .is_some_and(|a| a.iter().any(|n| n["ssid"] == SSID))
        },
    )?;
    let net = seen["result"]["networks"]
        .as_array()
        .and_then(|a| a.iter().find(|n| n["ssid"] == SSID))
        .cloned()
        .unwrap_or(Value::Null);
    check(
        net["security"] == "wpa2-wpa3" && net["joinable"] == true && net["channel"] == 1,
        format!("the access point in the scan: {net}"),
    )?;
    nums.put(
        "scan",
        format!(
            "{SSID} heard in {:.1} s ({} dBm, channel 1, wpa2-wpa3)",
            t.elapsed().as_secs_f64(),
            net["signal"]
        ),
    );

    // Join: WPA3 where the access point offers it.
    let t = Instant::now();
    set(
        vm,
        log,
        &serde_json::json!({"name": "wifi2", "ssid": SSID, "passphrase": PASSPHRASE}),
    )?;
    let m = monitor(vm, log, 40, |m| m["state"] == "connected")?;
    check(
        m["security"] == "wpa3" && m["pmf"] == true && m["bssid"] == AP_BSSID && m["channel"] == 1,
        format!("the link: {m}"),
    )?;
    check(
        m["signal"].is_i64() && m["driver"] == "mac80211_hwsim",
        format!("the link: {m}"),
    )?;
    nums.put(
        "join (security=auto)",
        format!(
            "connected in {:.1} s: WPA3 (SAE), PMF, {} dBm",
            t.elapsed().as_secs_f64(),
            m["signal"]
        ),
    );
    let row = until(vm, log, 10, "interface.list", "{}", |v| {
        v["result"].as_array().is_some_and(|a| {
            a.iter()
                .any(|i| i["name"] == "wifi2" && i["running"] == true)
        })
    });
    check(row.is_ok(), "wifi2 has no carrier in interface.list")?;

    // Frames across the encrypted link. The two radios are in one kernel, so
    // an IPv4 address of one is local to the other and never leaves; a
    // link-local IPv6 address is looked up on the interface named, and the
    // echo goes over the air: from the station to the access point's
    // address and back, with the router's own ping (`tool.ping.start`).
    let ll = sh(
        vm,
        log,
        "{ ip -6 addr show dev wifi1 | grep -o 'fe80::[0-9a-f:]*' | head -n 1; echo .; }",
    )?;
    let ll = ll.split_whitespace().next().unwrap_or("").to_owned();
    check(
        ll.starts_with("fe80::"),
        format!("the access point's radio has no link-local address: {ll}"),
    )?;
    // The station's own link-local address is tentative for a second after
    // the carrier (duplicate address detection): no source until then.
    let own = sh(
        vm,
        log,
        "{ i=0; while [ $i -lt 50 ]; do ip -6 addr show dev wifi2 scope link | grep fe80 | grep -qv tentative && break; sleep 0.2; i=$((i+1)); done; ip -6 addr show dev wifi2 scope link | grep -c tentative; }",
    )?;
    check(
        own.trim() == "0",
        format!("wifi2's link-local address never left 'tentative': {own}"),
    )?;
    let job = vm.ok(
        log,
        "tool.ping.start",
        &serde_json::json!({"address": ll, "interface": "wifi2", "count": 3, "interval_ms": 300})
            .to_string(),
    )?;
    let poll = serde_json::json!({"id": job["id"]}).to_string();
    let done = until(vm, log, 30, "tool.task.poll", &poll, |v| {
        v["result"]["done"] == true
    })?;
    let target = &done["result"]["summary"]["targets"][0];
    check(
        target["sent"] == 3 && target["received"] == 3,
        format!(
            "no echo across the link ({ll} from wifi2): {}",
            done["result"]
        ),
    )?;
    nums.put(
        "data across the link",
        format!(
            "3 of 3 echoes from the station to the access point ({ll}), avg {} ms",
            target["avg_ms"]
        ),
    );
    let rss = sh(
        vm,
        log,
        "{ for p in wpa_supplicant corerouter-daemon; do printf '%s=%s ' $p $(grep VmRSS /proc/$(pidof $p)/status | tr -s ' ' | cut -d' ' -f2); done; }",
    )?;
    nums.put("RSS KiB, connected", rss);

    // The passphrase is in the supplicant's memory and sealed in the
    // configuration: on no file in clear.
    let leak = sh(
        vm,
        log,
        &format!(
            "{{ grep -rl '{PASSPHRASE}' /config /run /var /etc 2>/dev/null | head -n 3; echo END; }}"
        ),
    )?;
    check(
        leak.trim() == "END",
        format!("the passphrase is on a file: {leak}"),
    )?;
    nums.put(
        "passphrase at rest",
        "in no file under /config, /run, /var, /etc",
    );

    // A wrong passphrase: said, and nothing connected.
    let t = Instant::now();
    set(
        vm,
        log,
        &serde_json::json!({"name": "wifi2", "passphrase": "esta-nao-e-a-senha"}),
    )?;
    let m = monitor(vm, log, 60, |m| m["failure"]["code"] == "wrong-key")?;
    check(
        m["state"] != "connected",
        format!("connected with a wrong passphrase: {m}"),
    )?;
    nums.put(
        "wrong passphrase",
        format!("failure wrong-key in {:.1} s", t.elapsed().as_secs_f64()),
    );

    // WPA2 forced, then WPA3 forced, against the same access point.
    for (security, want) in [("wpa2", "wpa2"), ("wpa3", "wpa3")] {
        let t = Instant::now();
        set(
            vm,
            log,
            &serde_json::json!({"name": "wifi2", "passphrase": PASSPHRASE, "security": security}),
        )?;
        // The link of before stays up until the next tick tells the radio.
        let m = monitor(vm, log, 60, |m| {
            m["state"] == "connected" && m["failure"].is_null() && m["security"] == want
        })?;
        nums.put(
            &format!("join (security={security})"),
            format!("connected in {:.1} s, {want}", t.elapsed().as_secs_f64()),
        );
    }

    // A network that is not there.
    set(
        vm,
        log,
        &serde_json::json!({"name": "wifi2", "ssid": "Nao-Existe", "security": "auto"}),
    )?;
    monitor(vm, log, 60, |m| m["failure"]["code"] == "not-found")?;
    nums.put("a network that is not there", "failure not-found");

    // The access point goes away and comes back: the router is told
    // nothing, and gets back on by itself.
    set(vm, log, &serde_json::json!({"name": "wifi2", "ssid": SSID}))?;
    monitor(vm, log, 60, |m| m["state"] == "connected")?;
    sh(
        vm,
        log,
        "{ kill $(pidof hostapd); sleep 1; pidof hostapd || echo gone; }",
    )?;
    monitor(vm, log, 60, |m| m["state"] != "connected")?;
    let t = Instant::now();
    start_ap(vm, log)?;
    let m = monitor(vm, log, 90, |m| m["state"] == "connected")?;
    check(
        m["reconnects"].as_u64().is_some_and(|n| n >= 1),
        format!("the lost link was not counted: {m}"),
    )?;
    nums.put(
        "access point restarted",
        format!("back on by itself in {:.1} s", t.elapsed().as_secs_f64()),
    );
    let h = vm
        .ok(log, "interface.wifi.history", r#"{"name":"wifi2"}"#)?
        .to_string();
    check(
        h.contains("connected to") && h.contains("disconnected") && h.contains("failed"),
        format!("the history: {h}"),
    )?;

    // Off: the radio leaves, and the supplicant ends with its last radio.
    vm.ok(log, "interface.wifi.disable", r#"{"name":"wifi2"}"#)?;
    until(vm, log, 20, "interface.wifi.list", "{}", |v| {
        v["result"][0]["state"] == "disabled"
    })?;
    let gone = sh(
        vm,
        log,
        "{ i=0; while [ $i -lt 50 ] && pidof wpa_supplicant >/dev/null; do sleep 0.2; i=$((i+1)); done; pidof wpa_supplicant >/dev/null || echo gone; echo .; }",
    )?;
    check(
        gone.contains("gone"),
        "wpa_supplicant still runs with no radio on",
    )?;
    nums.put("radio off", "left the network; wpa_supplicant ended");
    Ok(())
}

pub fn wifi_test(root: &Path, images: &Path, args: &[String]) -> Result<(), String> {
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
    let work = super::out_dir(root)?.join("wifi-test");
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work).map_err(|e| e.to_string())?;
    let tools = tools_disk(images, &work)?;
    let log_path = work.join("console.log");
    let mut log = std::fs::File::create(&log_path).map_err(|e| e.to_string())?;
    let kvm = !tcg && super::kvm_usable();
    eprintln!(
        "wifi-test ({}), console → {}",
        if kvm { "KVM" } else { "TCG" },
        log_path.display()
    );
    let started = Instant::now();
    let mut nums = Numbers(Vec::new());
    let mut vm = boot(&work, images, &tools, kvm, &mut log)?;
    let r = vm.expect_all(
        &mut log,
        &[
            "ready:",
            "maintenance shell",
            "wifi: 2 test radios",
            "wifi names:",
        ],
        120,
    )?;
    nums.put(
        "kernel → daemon ready",
        ready_s(r.first().map_or("", String::as_str)),
    );
    if let Err(e) = run(&mut vm, &mut log, &mut nums) {
        let diag = sh(
            &mut vm,
            &mut log,
            "{ ls /sys/class/net; pidof hostapd wpa_supplicant; grep -iE 'wifi|wpa|wireless' /var/log/corerouter-daemon.log | tail -n 20; dmesg | tail -n 15; }",
        )
        .unwrap_or_default();
        let m = vm
            .run(&mut log, "interface.wifi.monitor", r#"{"name":"wifi2"}"#)
            .unwrap_or_default();
        let h = vm
            .run(&mut log, "interface.wifi.history", "{}")
            .unwrap_or_default();
        eprintln!("   DIAG {diag}\n   MONITOR {m}\n   HISTORY {h}");
        return Err(e);
    }
    vm.poweroff(&mut log)?;
    eprintln!(
        "\nwifi-test ok in {:.1} s ({}):",
        started.elapsed().as_secs_f64(),
        if kvm { "KVM" } else { "TCG" }
    );
    for (k, v) in &nums.0 {
        eprintln!("  {k}: {v}");
    }
    let _ = std::fs::remove_file(work.join("r.qcow2"));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_access_point_offers_wpa2_and_wpa3_on_the_unmanaged_radio() {
        let c = hostapd_conf();
        assert!(c.contains("interface=wifi1\n"));
        assert!(c.contains("wpa_key_mgmt=WPA-PSK SAE\n") && c.contains("ieee80211w=1\n"));
        assert!(c.contains(&format!("ssid={SSID}\n")));
        assert!((8..=63).contains(&PASSPHRASE.len()));
        assert!(c.lines().all(|l| l.contains('=')));
    }
}

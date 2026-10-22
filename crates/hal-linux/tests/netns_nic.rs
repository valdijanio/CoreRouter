//! The interface dialog's data (G1.19) from a real kernel, inside a
//! throwaway network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_nic
//! ```
//!
//! A veth pair stands in for a NIC: the kernel reports 10 Gb/s full
//! duplex for it over ethtool netlink, counts its frames and its carrier
//! transitions. Like the other netns tests, these refuse to run unless the
//! namespace holds nothing but `lo`.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use corerouter_hal::{Hal, HalError, LinkCounters};
use corerouter_hal_linux::LinuxHal;
use corerouter_hal_linux::l2::LldpIo;
use corerouter_model::IfName;

const ENV: &str = "COREROUTER_NETNS_TESTS";

/// The tests share the namespace: one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!(
            "skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net` \
             (cargo xtask netns)"
        );
        return false;
    }
    static FRESH: OnceLock<Result<(), String>> = OnceLock::new();
    let fresh = FRESH.get_or_init(|| {
        let text = ip(&["-o", "link", "show"]);
        let names: Vec<&str> = text
            .lines()
            .filter_map(|l| l.split(':').nth(1))
            .map(str::trim)
            .collect();
        if names == ["lo"] {
            Ok(())
        } else {
            Err(format!(
                "{ENV}=1 but this network namespace has {names:?}, not just lo; refusing to \
                 touch it (run inside `unshare --user --map-root-user --net`)"
            ))
        }
    });
    if let Err(e) = fresh {
        panic!("{e}");
    }
    true
}

fn ip(args: &[&str]) -> String {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "ip {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn n(s: &str) -> IfName {
    s.parse().unwrap()
}

/// A veth pair `a`/`b`, both up; removed when dropped.
struct Pair(&'static str);

impl Pair {
    fn new(a: &'static str, b: &'static str) -> Self {
        ip(&["link", "add", a, "type", "veth", "peer", "name", b]);
        ip(&["link", "set", a, "up"]);
        ip(&["link", "set", b, "up"]);
        Pair(a)
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        let _ = Command::new("ip").args(["link", "del", self.0]).status();
    }
}

fn counter(c: &LinkCounters, group: &str, name: &str) -> u64 {
    c.groups
        .iter()
        .find(|g| g.name == group)
        .and_then(|g| g.counters.iter().find(|x| x.name == name))
        .map(|x| x.value)
        .unwrap_or_else(|| panic!("no {group}/{name} in {c:?}"))
}

/// Poll `f` until it holds (carrier changes are asynchronous).
fn eventually(mut f: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed().as_secs() < 3 {
        if f() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    false
}

#[test]
fn veth_reports_speed_duplex_and_link_downs() {
    if !in_netns() {
        return;
    }
    let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _pair = Pair::new("nica", "nicb");
    let mut hal = LinuxHal::new();
    assert!(eventually(|| hal
        .ethernet_monitor(&n("nica"))
        .unwrap()
        .link_ok));
    let m = hal.ethernet_monitor(&n("nica")).unwrap();
    assert_eq!(m.speed_mbps, Some(10_000), "{m:?}");
    assert_eq!(m.full_duplex, Some(true), "{m:?}");
    assert_eq!(m.autoneg, Some(false), "{m:?}");
    let downs = m.link_downs.expect("IFLA_CARRIER_DOWN_COUNT");
    let changes = m.carrier_changes.expect("IFLA_CARRIER_CHANGES");

    // Taking the peer down drops our carrier: one more link down.
    ip(&["link", "set", "nicb", "down"]);
    assert!(eventually(|| !hal
        .ethernet_monitor(&n("nica"))
        .unwrap()
        .link_ok));
    let m = hal.ethernet_monitor(&n("nica")).unwrap();
    assert_eq!(m.link_downs, Some(downs + 1));
    assert_eq!(m.speed_mbps, None, "no rate without a link");
    ip(&["link", "set", "nicb", "up"]);
    assert!(eventually(|| hal
        .ethernet_monitor(&n("nica"))
        .unwrap()
        .link_ok));
    let m = hal.ethernet_monitor(&n("nica")).unwrap();
    assert_eq!(m.link_downs, Some(downs + 1));
    assert_eq!(m.carrier_changes, Some(changes + 2));
}

#[test]
fn veth_counts_frames_both_ways() {
    if !in_netns() {
        return;
    }
    let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _pair = Pair::new("cnta", "cntb");
    let mut hal = LinuxHal::new();
    let before_a = hal.counters(&n("cnta")).unwrap();
    let before_b = hal.counters(&n("cntb")).unwrap();
    let mut io = LldpIo::new(std::time::Duration::from_secs(30));
    assert!(io.set_interfaces(&[n("cnta")]).is_empty());
    for _ in 0..5 {
        io.send(&n("cnta"), &[0u8; 64], Instant::now()).unwrap();
    }
    let after_a = hal.counters(&n("cnta")).unwrap();
    let after_b = hal.counters(&n("cntb")).unwrap();
    let tx = |c: &LinkCounters| counter(c, "interface", "tx_packets");
    let rx = |c: &LinkCounters| counter(c, "interface", "rx_packets");
    assert!(tx(&after_a) >= tx(&before_a) + 5, "{after_a:?}");
    assert!(rx(&after_b) >= rx(&before_b) + 5, "{after_b:?}");
    assert!(counter(&after_b, "interface", "rx_bytes") >= 5 * 64);
    assert_eq!(counter(&after_b, "interface", "rx_crc_errors"), 0);
}

#[test]
fn veth_hardware_is_a_software_link() {
    if !in_netns() {
        return;
    }
    let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let _pair = Pair::new("hwa", "hwb");
    let mut hal = LinuxHal::new();
    let hw = hal.hardware(&n("hwa")).unwrap();
    assert_eq!(hw.driver.as_deref(), Some("veth"), "{hw:?}");
    assert_eq!(hw.bus.as_deref(), Some("virtual"));
    assert_eq!(hw.vendor_id, None);
    assert!(hw.mac.is_some());
    assert!(hw.max_mtu.is_some_and(|m| m >= 1500), "{hw:?}");
    assert!(hw.rx_queues.is_some());
    // veth implements the features query: GSO is on by default.
    assert!(
        hw.offloads.iter().any(|o| o.name == "GSO" && o.active),
        "{hw:?}"
    );
}

#[test]
fn unsupported_queries_are_notes_and_missing_links_errors() {
    if !in_netns() {
        return;
    }
    let _one = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut hal = LinuxHal::new();
    // `lo` has no PHY: the monitor answers, with what is missing noted.
    let m = hal.ethernet_monitor(&n("lo")).unwrap();
    assert_eq!(m.speed_mbps, None);
    assert!(!m.notes.is_empty(), "{m:?}");
    assert!(!hal.counters(&n("lo")).unwrap().groups.is_empty());
    for r in [
        hal.ethernet_monitor(&n("nosuch0")).map(|_| ()),
        hal.hardware(&n("nosuch0")).map(|_| ()),
        hal.counters(&n("nosuch0")).map(|_| ()),
    ] {
        assert!(matches!(r, Err(HalError::Rejected(_))), "{r:?}");
    }
}

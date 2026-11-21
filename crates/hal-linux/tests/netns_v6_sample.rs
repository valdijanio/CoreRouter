//! G1.3i: the clock's link sample carries the IPv6 state of the managed
//! links, read with the session unlocked; `ipv6_learned` and
//! `address_states` answer from it what a dump of the kernel answers, and
//! the route read brings the RA routes only (the kernel filters a strict
//! dump by protocol), not the rest of the table. Inside a throwaway network
//! namespace; run by `cargo xtask netns` (see `tests/netns.rs` for the
//! guard).
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};

use corerouter_hal::{Hal, Learned};
use corerouter_hal_linux::LinuxHal;
use corerouter_model::ipv6::AcceptRa;
use corerouter_model::{Config, IfName, Interface, InterfaceKind};

const ENV: &str = "COREROUTER_NETNS_TESTS";

/// One test at a time: they share the namespace's links.
static SERIAL: Mutex<()> = Mutex::new(());

fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!("skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net`");
        return false;
    }
    static FRESH: OnceLock<Vec<String>> = OnceLock::new();
    let names = FRESH.get_or_init(|| {
        let out = Command::new("ip")
            .args(["-o", "link", "show"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter_map(|l| l.split(':').nth(1))
            .map(|n| n.trim().to_owned())
            .collect()
    });
    assert_eq!(names, &["lo"], "{ENV}=1 outside a fresh network namespace");
    true
}

/// `ip -batch` of `lines`.
fn ip_batch(lines: &[&str]) {
    let mut child = Command::new("ip")
        .args(["-batch", "-"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(lines.join("\n").as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn config(port: &IfName, ra: bool) -> Config {
    let mut cfg = Config::default();
    cfg.interfaces.insert(
        port.clone(),
        Interface::new(port.clone(), InterfaceKind::Ethernet),
    );
    if ra {
        cfg.ipv6.settings.accept_router_advertisements = AcceptRa::Yes;
    }
    cfg
}

/// The clock's read and fold, as `control::clock` does it.
fn clock(hal: &mut LinuxHal) {
    let sample = hal.link_reader().unwrap().read();
    hal.poll_sample(sample).unwrap();
}

fn sorted<T: std::fmt::Debug>(v: Vec<T>) -> Vec<String> {
    let mut out: Vec<String> = v.iter().map(|x| format!("{x:?}")).collect();
    out.sort();
    out
}

/// `l` with its lifetimes as they would read `by` seconds later, so two
/// reads a second apart compare equal.
fn later(l: &Learned, by: u32) -> Learned {
    let f = |s: Option<u32>| s.map(|s| s.saturating_sub(by));
    match l.clone() {
        Learned::Address {
            interface,
            address,
            valid_secs,
            preferred_secs,
        } => Learned::Address {
            interface,
            address,
            valid_secs: f(valid_secs),
            preferred_secs: f(preferred_secs),
        },
        Learned::Route {
            interface,
            dst,
            gateway,
            metric,
            table,
            expires_secs,
        } => Learned::Route {
            interface,
            dst,
            gateway,
            metric,
            table,
            expires_secs: f(expires_secs),
        },
    }
}

#[test]
fn the_sample_answers_the_ipv6_reads_like_the_kernel() {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !in_netns() {
        return;
    }
    ip_batch(&["link add v6p type dummy", "link set v6p up"]);
    let port: IfName = "v6p".parse().unwrap();
    let cfg = config(&port, true);
    let mut hal = LinuxHal::new();
    hal.apply(&Config::default(), &cfg).unwrap();
    // What RA would have left: an address with a lifetime, a deprecated
    // one (preferred lifetime over), an `ra` route; and a BGP route.
    ip_batch(&[
        "addr add 2001:db8:1::1/64 dev v6p valid_lft 3600 preferred_lft 1800",
        "addr add 2001:db8:2::1/64 dev v6p valid_lft 3600 preferred_lft 0",
        "route add 2001:db8:a::/64 dev v6p proto ra expires 1800",
        "route add 2001:db8:b::/64 dev v6p proto bgp",
    ]);
    clock(&mut hal);
    let learned = hal.ipv6_learned().unwrap();
    let states = hal.address_states().unwrap();

    // The kernel asked now, by a hal with no sample.
    let mut fresh = LinuxHal::new();
    fresh.apply(&Config::default(), &cfg).unwrap();
    fresh.poll();
    let kernel_learned = fresh.ipv6_learned().unwrap();
    fresh.poll();
    let kernel_states = fresh.address_states().unwrap();
    // Equal, but for a lifetime that ticked over between the two reads (the
    // sample's count down from when it was read).
    let same = (0..=1).any(|by| {
        let ours: Vec<Learned> = learned.iter().map(|l| later(l, by)).collect();
        sorted(ours) == sorted(kernel_learned.clone())
    });
    assert!(same, "{learned:?}\n{kernel_learned:?}");
    let strip = |v: &[corerouter_hal::address_state::AddressState]| {
        sorted(
            v.iter()
                .map(|s| {
                    (
                        s.interface.clone(),
                        s.address,
                        s.tentative,
                        s.dad_failed,
                        s.deprecated,
                    )
                })
                .collect(),
        )
    };
    assert_eq!(strip(&states), strip(&kernel_states));

    let routes: Vec<String> = learned
        .iter()
        .filter_map(|l| match l {
            Learned::Route { dst, .. } => Some(dst.to_string()),
            Learned::Address { .. } => None,
        })
        .collect();
    assert_eq!(routes, ["2001:db8:a::/64"], "the RA route, not BGP's");
    assert!(
        learned.iter().any(
            |l| matches!(l, Learned::Address { address, .. } if address.to_string() == "2001:db8:1::1/64")
        ),
        "{learned:?}"
    );
    assert!(
        states
            .iter()
            .any(|s| s.deprecated && s.address.to_string() == "2001:db8:2::1/64"),
        "{states:?}"
    );

    // An apply drops the sample: the next reads ask the kernel again, and
    // see what changed since.
    ip_batch(&["route add 2001:db8:c::/64 dev v6p proto ra expires 1800"]);
    hal.apply(&cfg, &cfg).unwrap();
    hal.poll();
    let after = hal.ipv6_learned().unwrap();
    assert!(
        after.iter().any(
            |l| matches!(l, Learned::Route { dst, .. } if dst.to_string() == "2001:db8:c::/64")
        ),
        "{after:?}"
    );

    // RA turned off: the apply flushes what the port learned, and the
    // clock's read (which then skips the route walk) agrees with the kernel.
    let off = config(&port, false);
    hal.apply(&cfg, &off).unwrap();
    clock(&mut hal);
    assert!(hal.ipv6_learned().unwrap().is_empty());
    ip_batch(&["link del v6p"]);
}

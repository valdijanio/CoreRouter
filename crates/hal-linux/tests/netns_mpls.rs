//! G3.5 — MPLS label switching through our own rtnetlink code, against a
//! real kernel, inside a throwaway network namespace — no root, nothing
//! reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_mpls
//! ```
//!
//! A user namespace cannot load `mpls_router`: without it (no
//! `/proc/sys/net/mpls`) the tests skip, or fail with
//! `COREROUTER_REQUIRE_MPLS=1` (the CI loads it first,
//! `ci/kernel-modules/mpls_router`). `ip -f mpls route` checks the result
//! independently of our codec.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::process::Command;
use std::sync::Mutex;
use std::time::Instant;

use corerouter_hal::Hal;
use corerouter_hal::mpls::{MplsNexthop, MplsReader, MplsRoute, Origin, StaticOp};
use corerouter_hal_linux::LinuxHal;
use corerouter_hal_linux::mpls::{Reader, apply_one_by_one, apply_static, available};
use corerouter_model::mpls::{MplsInterface, StaticLsp};
use corerouter_model::{Config, IfName, Interface, InterfaceKind};

const ENV: &str = "COREROUTER_NETNS_TESTS";
const REQUIRE: &str = "COREROUTER_REQUIRE_MPLS";
/// The tests share the namespace's label table: one at a time.
static ONE: Mutex<()> = Mutex::new(());

fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!(
            "skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net` (cargo xtask netns)"
        );
        return false;
    }
    let out = Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let names: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split(':').nth(1))
        .map(str::trim)
        .map(|n| n.split('@').next().unwrap_or(n))
        .collect();
    assert!(
        names.iter().all(|n| *n == "lo" || n.starts_with("mp")),
        "{ENV}=1 but this namespace has {names:?}; refusing to touch it"
    );
    if !available() {
        assert!(
            std::env::var_os(REQUIRE).is_none_or(|v| v != "1"),
            "{REQUIRE}=1 but this kernel has no mpls_router"
        );
        eprintln!("skipped: no mpls_router (load it on the host: modprobe mpls_router)");
        return false;
    }
    true
}

fn ip(args: &[&str]) -> String {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// A veth pair `<a>`/`<b>`, `a` with 10.<net>.0.1/24, both up.
fn port(a: &str, b: &str, net: u8) {
    let _ = Command::new("ip").args(["link", "del", a]).output();
    ip(&["link", "add", a, "type", "veth", "peer", "name", b]);
    ip(&["addr", "add", &format!("10.{net}.0.1/24"), "dev", a]);
    ip(&["link", "set", a, "up"]);
    ip(&["link", "set", b, "up"]);
}

fn sysctl(path: &str, v: &str) {
    std::fs::write(format!("/proc/sys/net/mpls/{path}"), v).unwrap();
}

fn route(label: u32, via: [u8; 4], dev: &str, out: &[u32]) -> MplsRoute {
    MplsRoute {
        label,
        origin: Origin::Static,
        nexthops: vec![MplsNexthop {
            via: Some(IpAddr::from(via)),
            interface: Some(dev.parse().unwrap()),
            out_labels: out.to_vec(),
        }],
    }
}

fn mine(r: &mut Reader) -> Vec<MplsRoute> {
    r.routes()
        .unwrap()
        .into_iter()
        .filter(|r| r.origin == Origin::Static)
        .collect()
}

#[test]
fn static_labels_go_in_and_read_back() {
    if !in_netns() {
        return;
    }
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    port("mpa0", "mpa1", 30);
    sysctl("platform_labels", "100000");
    let ops = vec![
        StaticOp::Set(route(100, [10, 30, 0, 2], "mpa0", &[200])),
        StaticOp::Set(route(101, [10, 30, 0, 2], "mpa0", &[])),
        StaticOp::Set(route(102, [10, 30, 0, 2], "mpa0", &[300, 301, 302])),
    ];
    apply_static(&ops, &[]).unwrap();
    let text = ip(&["-f", "mpls", "route", "show"]);
    assert!(
        text.contains("100 as to 200 via inet 10.30.0.2 dev mpa0"),
        "{text}"
    );
    assert!(
        text.contains("102 as to 300/301/302 via inet 10.30.0.2 dev mpa0"),
        "{text}"
    );
    assert!(text.contains("101 via inet 10.30.0.2 dev mpa0"), "{text}");
    let mut r = Reader::open().unwrap();
    let back = mine(&mut r);
    assert_eq!(
        back,
        vec![
            route(100, [10, 30, 0, 2], "mpa0", &[200]),
            route(101, [10, 30, 0, 2], "mpa0", &[]),
            route(102, [10, 30, 0, 2], "mpa0", &[300, 301, 302]),
        ]
    );
    // An entry `ip` added is read too (another program's), with its origin.
    ip(&[
        "-f",
        "mpls",
        "route",
        "add",
        "500",
        "via",
        "inet",
        "10.30.0.3",
        "dev",
        "mpa0",
        "proto",
        "193",
    ]);
    let all = r.routes().unwrap();
    assert!(
        all.iter()
            .any(|x| x.label == 500 && x.origin == Origin::Ldp),
        "{all:?}"
    );
    // A refusal in the middle undoes what went before (all or nothing):
    // label 99999 is in range, 200000 is not (platform_labels 100000).
    let before = back.clone();
    let bad = vec![
        StaticOp::Remove(100),
        StaticOp::Set(route(103, [10, 30, 0, 2], "mpa0", &[])),
        StaticOp::Set(route(200_000, [10, 30, 0, 2], "mpa0", &[])),
    ];
    assert!(apply_static(&bad, &before).is_err());
    assert_eq!(mine(&mut r), before, "the batch was undone");
    apply_static(
        &[
            StaticOp::Remove(100),
            StaticOp::Remove(101),
            StaticOp::Remove(102),
            StaticOp::Remove(100),
        ],
        &before,
    )
    .unwrap();
    assert!(mine(&mut r).is_empty());
    ip(&["link", "del", "mpa0"]);
}

#[test]
fn apply_sets_the_knobs_and_the_static_entries() {
    if !in_netns() {
        return;
    }
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    port("mpb0", "mpb1", 31);
    let name: IfName = "mpb0".parse().unwrap();
    let mut from = Config::default();
    from.interfaces.insert(
        name.clone(),
        Interface::new(name.clone(), InterfaceKind::Ethernet),
    );
    let mut to = from.clone();
    to.routing.mpls.settings.dynamic_label_range = (16, 49_999);
    to.routing.mpls.settings.propagate_ttl = false;
    to.routing.mpls.interfaces.insert(
        "mpb0".into(),
        MplsInterface {
            input: true,
            disabled: false,
            comment: String::new(),
        },
    );
    to.routing.mpls.statics.insert(
        60_000,
        StaticLsp {
            nexthop: IpAddr::from([10, 31, 0, 2]),
            interface: Some(name.clone()),
            out_labels: vec![70],
            disabled: false,
            comment: String::new(),
        },
    );
    let mut hal = LinuxHal::with_policy(corerouter_hal_linux::owner::Policy::default());
    // The config names the port first: only then is it managed (owner rule 5).
    hal.apply(&Config::default(), &from).unwrap();
    // The label is above the table (platform_labels = 50 000): refused,
    // and nothing stays.
    assert!(hal.apply(&from, &to).is_err());
    to.routing.mpls.settings.dynamic_label_range = (16, 99_999);
    hal.apply(&from, &to).unwrap();
    let read = |p: &str| std::fs::read_to_string(format!("/proc/sys/net/mpls/{p}")).unwrap();
    assert_eq!(read("platform_labels").trim(), "100000");
    assert_eq!(read("ip_ttl_propagate").trim(), "0");
    assert_eq!(read("conf/mpb0/input").trim(), "1");
    let got = hal.mpls_routes().unwrap();
    assert!(
        got.iter()
            .any(|r| r.label == 60_000 && r.nexthops[0].out_labels == [70]),
        "{got:?}"
    );
    hal.apply(&to, &from).unwrap();
    assert_eq!(read("conf/mpb0/input").trim(), "0");
    assert!(!hal.mpls_routes().unwrap().iter().any(|r| r.label == 60_000));
    ip(&["link", "del", "mpb0"]);
}

#[test]
fn ten_thousand_labels_in_batches_and_one_by_one() {
    if !in_netns() {
        return;
    }
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    port("mpc0", "mpc1", 32);
    sysctl("platform_labels", "1048575");
    const N: u32 = 10_000;
    let set: Vec<StaticOp> = (0..N)
        .map(|i| StaticOp::Set(route(100_000 + i, [10, 32, 0, 2], "mpc0", &[200_000 + i])))
        .collect();
    let remove: Vec<StaticOp> = (0..N).map(|i| StaticOp::Remove(100_000 + i)).collect();
    let t = Instant::now();
    apply_static(&set, &[]).unwrap();
    let batched = t.elapsed();
    let mut r = Reader::open().unwrap();
    let t = Instant::now();
    let n = mine(&mut r).len();
    let dump = t.elapsed();
    assert_eq!(n, N as usize);
    apply_static(&remove, &[]).unwrap();
    let t = Instant::now();
    apply_one_by_one(&set).unwrap();
    let single = t.elapsed();
    apply_static(&remove, &[]).unwrap();
    eprintln!("{N} labels: batched {batched:?}, one by one {single:?}, dump {dump:?}");
    assert!(mine(&mut r).is_empty());
    ip(&["link", "del", "mpc0"]);
}

//! G1.31c — the encrypted packets of WireGuard by a VRF, against a real
//! kernel, in a throwaway network namespace (no root, nothing reaches the
//! host; `cargo xtask netns` runs it):
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_wireguard_vrf
//! ```
//!
//! Veth `wva` is in VRF `vblue`, its peer `wvb` in VRF `vred`: the address
//! across is reachable only through those VRFs' tables (a VRF member's
//! local and connected routes live in its table, not in `local`/`main`).
//! WireGuard `wgva` (vrf=vblue) calls `wgvb` (vrf=vred) at 10.79.0.2:
//!
//! - with the `vrf` (fwmark = the VRF's routing mark, a rule to its table,
//!   `udp_l3mdev_accept=1`, all from one `apply`), the handshake happens;
//! - `wgvc`, the same call without a `vrf`, never shakes hands (its
//!   socket looks in `main`, which has no way there), until its `vrf` is
//!   set; then it does;
//! - taking the `vrf`s out removes the rules and puts the sysctl back.
//!
//! A user namespace cannot load the `wireguard` module: without it the
//! test skips, or fails with `COREROUTER_REQUIRE_WIREGUARD=1`.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::process::Command;
use std::time::{Duration, Instant};

use corerouter_hal::Hal;
use corerouter_hal::policy::wireguard_fwmark;
use corerouter_hal::wireguard::{Key, WgDevice, WgPeerSpec};
use corerouter_hal_linux::{LinuxHal, Policy};
use corerouter_model::wireguard::Wireguard;
use corerouter_model::{AddressEntry, Config, IfName, Interface, InterfaceKind};

const ENV: &str = "COREROUTER_NETNS_TESTS";
const REQUIRE: &str = "COREROUTER_REQUIRE_WIREGUARD";

fn ready() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!("skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net`");
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
        .collect();
    assert!(
        names == ["lo"],
        "{ENV}=1 but this namespace has {names:?}; refusing to touch it"
    );
    let made = |args: &[&str]| {
        Command::new("ip")
            .args(args)
            .output()
            .unwrap()
            .status
            .success()
    };
    let wg = made(&["link", "add", "wgprobe", "type", "wireguard"]);
    let vrf = made(&["link", "add", "vrfprobe", "type", "vrf", "table", "4242"]);
    let _ = Command::new("ip").args(["link", "del", "wgprobe"]).output();
    let _ = Command::new("ip")
        .args(["link", "del", "vrfprobe"])
        .output();
    if !(wg && vrf) {
        assert!(
            std::env::var_os(REQUIRE).is_none_or(|v| v != "1"),
            "{REQUIRE}=1 but this kernel cannot create a wireguard ({wg}) or vrf ({vrf}) link"
        );
        eprintln!("skipped: this kernel has no WireGuard or VRF (modules wireguard, vrf)");
        return false;
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

fn hex(s: &str) -> Key {
    let v: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    v.try_into().unwrap()
}

/// RFC 7748 §6.1.
fn alice() -> (Key, Key) {
    (
        hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"),
        hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"),
    )
}

fn bob() -> (Key, Key) {
    (
        hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"),
        hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"),
    )
}

fn l3mdev_accept() -> String {
    std::fs::read_to_string("/proc/sys/net/ipv4/udp_l3mdev_accept")
        .unwrap()
        .trim()
        .to_owned()
}

/// Ports `wva` (vblue) and `wvb` (vred) with their addresses, and three
/// WireGuard links with these `vrf`s.
fn config(vrfs: [Option<&str>; 3]) -> Config {
    let mut c = Config::default();
    for (name, table) in [("vblue", 1101), ("vred", 1102)] {
        c.interfaces.insert(
            n(name),
            Interface::new(n(name), InterfaceKind::Vrf { table }),
        );
    }
    for (port, vrf, addr) in [
        ("wva", "vblue", "10.79.0.1/24"),
        ("wvb", "vred", "10.79.0.2/24"),
    ] {
        let mut i = Interface::new(n(port), InterfaceKind::Ethernet);
        i.vrf = Some(n(vrf));
        c.interfaces.insert(n(port), i);
        let id = c.ip.next_address_id();
        c.ip.addresses.push(AddressEntry {
            id,
            address: addr.parse().unwrap(),
            interface: n(port),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
    }
    let links = [("wgva", 51840u16), ("wgvb", 51841), ("wgvc", 51842)];
    for ((name, port), vrf) in links.into_iter().zip(vrfs) {
        let mut w = Wireguard::new(port);
        w.vrf = vrf.map(n);
        c.interfaces.insert(
            n(name),
            Interface::new(n(name), InterfaceKind::Wireguard(Box::new(w))),
        );
    }
    c
}

fn wg_of<'a>(c: &'a Config, name: &str) -> &'a Wireguard {
    match &c.interfaces.get(&n(name)).unwrap().kind {
        InterfaceKind::Wireguard(w) => w,
        _ => panic!("{name} is not WireGuard"),
    }
}

/// Push the keys: `wgva` and `wgvc` (Alice) call Bob at `wgvb`.
fn push(hal: &mut LinuxHal, c: &Config) {
    let (a_priv, a_pub) = alice();
    let (b_priv, b_pub) = bob();
    let caller = |port: u16, name: &str| WgDevice {
        private_key: a_priv,
        listen_port: port,
        fwmark: wireguard_fwmark(wg_of(c, name)),
        peers: vec![WgPeerSpec {
            public_key: b_pub,
            preshared_key: [0; 32],
            endpoint: "10.79.0.2:51841".parse().ok(),
            persistent_keepalive: 1,
            allowed: vec!["10.80.1.0/24".parse().unwrap()],
        }],
    };
    let callee = WgDevice {
        private_key: b_priv,
        listen_port: 51841,
        fwmark: wireguard_fwmark(wg_of(c, "wgvb")),
        peers: vec![WgPeerSpec {
            public_key: a_pub,
            preshared_key: [0; 32],
            endpoint: None,
            persistent_keepalive: 0,
            allowed: vec!["10.80.0.0/24".parse().unwrap()],
        }],
    };
    hal.wireguard_set(&n("wgvb"), &callee, &b_pub).unwrap();
    hal.wireguard_set(&n("wgva"), &caller(51840, "wgva"), &a_pub)
        .unwrap();
    hal.wireguard_set(&n("wgvc"), &caller(51842, "wgvc"), &a_pub)
        .unwrap();
}

/// Whether `name`'s peer has shaken hands within `wait`.
fn shook(hal: &mut LinuxHal, name: &str, wait: Duration) -> bool {
    let (_, b_pub) = bob();
    let start = Instant::now();
    loop {
        let s = hal.wireguard_status(&n(name), 0).unwrap();
        let done = s
            .peers
            .iter()
            .any(|p| p.public_key == b_pub && p.last_handshake_unix.is_some());
        if done {
            return true;
        }
        if start.elapsed() >= wait {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn the_handshake_goes_by_the_vrf_and_only_by_it() {
    if !ready() {
        return;
    }
    ip(&["link", "add", "wva", "type", "veth", "peer", "name", "wvb"]);
    let mut hal = LinuxHal::with_policy(Policy {
        manage: vec!["wva".into(), "wvb".into()],
        unmanaged: Vec::new(),
    });
    let before = l3mdev_accept();
    let empty = Config::default();
    let one = config([Some("vblue"), Some("vred"), None]);
    hal.apply(&empty, &one).unwrap();
    push(&mut hal, &one);

    // What one apply made: the marks of both VRFs to their tables, and the
    // sockets hear on VRF members.
    let rules = ip(&["rule"]);
    let blue = wireguard_fwmark(wg_of(&one, "wgva"));
    let red = wireguard_fwmark(wg_of(&one, "wgvb"));
    assert!(blue != 0 && red != 0 && blue != red);
    for (mark, table) in [(blue, 1101), (red, 1102)] {
        let want = format!("fwmark {mark:#x}/0xffff0000 iif lo lookup {table}");
        assert!(rules.contains(&want), "no `{want}` in:\n{rules}");
    }
    assert_eq!(l3mdev_accept(), "1");
    // Main has no way across: only the VRFs do.
    let main = Command::new("ip")
        .args(["route", "get", "10.79.0.2"])
        .output()
        .unwrap();
    assert!(!main.status.success(), "main reaches 10.79.0.2");

    assert!(
        shook(&mut hal, "wgva", Duration::from_secs(10)),
        "no handshake through the VRFs"
    );
    assert!(
        !shook(&mut hal, "wgvc", Duration::from_millis(1500)),
        "wgvc has no vrf: its socket looks in main and must not get there"
    );

    // The `vrf` set on wgvc: now it gets there too.
    let two = config([Some("vblue"), Some("vred"), Some("vblue")]);
    hal.apply(&one, &two).unwrap();
    // Its peer again, so the first handshake goes now and not at the
    // next retry (REKEY_TIMEOUT, 5 s): a new peer with a keepalive starts.
    let (a_priv, a_pub) = alice();
    let bare = WgDevice {
        private_key: a_priv,
        listen_port: 51842,
        fwmark: wireguard_fwmark(wg_of(&two, "wgvc")),
        peers: Vec::new(),
    };
    hal.wireguard_set(&n("wgvc"), &bare, &a_pub).unwrap();
    push(&mut hal, &two);
    assert!(
        shook(&mut hal, "wgvc", Duration::from_secs(12)),
        "no handshake once wgvc has vrf=vblue"
    );

    // Taken out: no mark rules left, the sysctl as it was.
    let none = config([None, None, None]);
    hal.apply(&two, &none).unwrap();
    let rules = ip(&["rule"]);
    assert!(!rules.contains(&format!("{blue:#x}")), "{rules}");
    assert!(!rules.contains(&format!("{red:#x}")), "{rules}");
    assert_eq!(l3mdev_accept(), before);
    hal.apply(&none, &empty).unwrap();
    let _ = Command::new("ip").args(["link", "del", "wva"]).output();
}

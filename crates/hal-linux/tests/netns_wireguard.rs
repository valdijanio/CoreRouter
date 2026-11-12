//! G1.31 — WireGuard through `LinuxHal` against a real kernel, inside a
//! throwaway network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_wireguard
//! ```
//!
//! (`cargo xtask netns` runs it in its own namespace.) Two WireGuard links
//! in the same namespace talk over the loopback: `apply` creates them,
//! `wireguard_set` gives them the keys of RFC 7748 §6.1 (Alice and Bob) and
//! each other as peer, and a keepalive makes them shake hands. A handshake
//! proves the whole path: keys, port, endpoint and allowed addresses as the
//! kernel took them from our generic netlink. Then a peer is added and one
//! removed while the first session stays up (the update is incremental).
//!
//! A user namespace cannot load the `wireguard` module: without it the
//! tests skip, or fail with `COREROUTER_REQUIRE_WIREGUARD=1` (the CI loads
//! it first, `ci/kernel-modules/wireguard`).
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
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use corerouter_hal::Hal;
use corerouter_hal::wireguard::{Key, WgDevice, WgPeerSpec, WgStatus};
use corerouter_hal_linux::LinuxHal;
use corerouter_model::wireguard::Wireguard;
use corerouter_model::{Config, IfName, Interface, InterfaceKind};

const ENV: &str = "COREROUTER_NETNS_TESTS";
const REQUIRE: &str = "COREROUTER_REQUIRE_WIREGUARD";

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
        let out = Command::new("ip")
            .args(["-o", "link", "show"])
            .output()
            .map_err(|e| format!("cannot run `ip`: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
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
    has_wireguard()
}

/// Whether this kernel can create a `wireguard` link, checked once.
fn has_wireguard() -> bool {
    static HAS: OnceLock<bool> = OnceLock::new();
    let has = *HAS.get_or_init(|| {
        let ok = Command::new("ip")
            .args(["link", "add", "wgprobe", "type", "wireguard"])
            .output()
            .unwrap()
            .status
            .success();
        if ok {
            ip(&["link", "del", "wgprobe"]);
        }
        ok
    });
    if !has {
        assert!(
            std::env::var_os(REQUIRE).is_none_or(|v| v != "1"),
            "{REQUIRE}=1 but this kernel cannot create a wireguard link \
             (CONFIG_WIREGUARD / module wireguard; on the host: modprobe wireguard)"
        );
        eprintln!("skipped: this kernel has no WireGuard (module wireguard)");
    }
    has
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

fn wg_config(names: &[&str]) -> Config {
    let mut cfg = Config::default();
    // The loopback carries the encrypted packets between the two links.
    ip(&["link", "set", "lo", "up"]);
    for (i, name) in names.iter().enumerate() {
        let port = 51820 + u16::try_from(i).unwrap();
        cfg.interfaces.insert(
            n(name),
            Interface::new(
                n(name),
                InterfaceKind::Wireguard(Box::new(Wireguard::new(port))),
            ),
        );
    }
    cfg
}

fn peer(public: Key, port: Option<u16>, allowed: &str, keepalive: u16) -> WgPeerSpec {
    WgPeerSpec {
        public_key: public,
        preshared_key: [0; 32],
        endpoint: port.map(|p| format!("127.0.0.1:{p}").parse().unwrap()),
        persistent_keepalive: keepalive,
        allowed: vec![allowed.parse().unwrap()],
    }
}

fn status(hal: &mut LinuxHal, name: &str) -> WgStatus {
    hal.wireguard_status(&n(name), 0).unwrap()
}

/// Wait until peer `public` of `name` has a handshake; its time.
fn handshake(hal: &mut LinuxHal, name: &str, public: &Key) -> u64 {
    let start = Instant::now();
    loop {
        let s = status(hal, name);
        if let Some(t) = s
            .peers
            .iter()
            .find(|p| p.public_key == *public)
            .and_then(|p| p.last_handshake_unix)
        {
            return t;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "no handshake on {name} in 10 s: {s:?}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn two_links_shake_hands_and_a_peer_change_keeps_the_session() {
    if !in_netns() {
        return;
    }
    let mut hal = LinuxHal::new();
    let cfg = wg_config(&["wgt0", "wgt1"]);
    hal.apply(&Config::default(), &cfg).unwrap();
    let kind = ip(&["-d", "-o", "link", "show", "dev", "wgt0"]);
    assert!(kind.contains("wireguard"), "{kind}");
    assert!(kind.contains(",UP"), "{kind}");

    let (a_priv, a_pub) = alice();
    let (b_priv, b_pub) = bob();
    let mut a = WgDevice {
        private_key: a_priv,
        listen_port: 51820,
        peers: vec![peer(b_pub, Some(51821), "10.77.1.0/24", 1)],
    };
    let b = WgDevice {
        private_key: b_priv,
        listen_port: 51821,
        peers: vec![peer(a_pub, None, "10.77.0.0/24", 0)],
    };
    hal.wireguard_set(&n("wgt1"), &b, &b_pub).unwrap();
    hal.wireguard_set(&n("wgt0"), &a, &a_pub).unwrap();

    // What the kernel holds is what we sent; its public key is Alice's
    // (the kernel derived it from the private key we gave).
    let s0 = status(&mut hal, "wgt0");
    assert_eq!(s0.listen_port, 51820);
    assert_eq!(s0.public_key, a_pub);
    assert_eq!(s0.peers.len(), 1);
    assert_eq!(s0.peers[0].endpoint, "127.0.0.1:51821".parse().ok());

    // The keepalive starts the handshake; Bob learns Alice's endpoint from it.
    let t0 = handshake(&mut hal, "wgt0", &b_pub);
    handshake(&mut hal, "wgt1", &a_pub);
    let s1 = status(&mut hal, "wgt1");
    assert_eq!(
        s1.peers[0].endpoint,
        "127.0.0.1:51820".parse().ok(),
        "roamed in"
    );

    // Pushing the same device again changes nothing.
    hal.wireguard_set(&n("wgt0"), &a, &a_pub).unwrap();
    // A second peer comes, the first stays with its session: same
    // handshake time (a re-created peer would start over at none) and its
    // counters keep counting.
    let rx_before = status(&mut hal, "wgt0").peers[0].rx_bytes;
    let (_, carol) = {
        let mut k = [9u8; 32];
        k[31] = 0x40;
        (
            k,
            hex("2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a"),
        )
    };
    a.peers.push(peer(carol, None, "10.77.2.0/24", 0));
    hal.wireguard_set(&n("wgt0"), &a, &a_pub).unwrap();
    let s0 = status(&mut hal, "wgt0");
    assert_eq!(s0.peers.len(), 2);
    let first = s0.peers.iter().find(|p| p.public_key == b_pub).unwrap();
    assert_eq!(
        first.last_handshake_unix,
        Some(t0),
        "the first session was kept"
    );
    assert!(first.rx_bytes >= rx_before);

    // Remove the new peer, change the port: the old peer stays.
    a.peers.pop();
    a.listen_port = 51830;
    hal.wireguard_set(&n("wgt0"), &a, &a_pub).unwrap();
    let s0 = status(&mut hal, "wgt0");
    assert_eq!(s0.listen_port, 51830);
    assert_eq!(s0.peers.len(), 1);
    assert_eq!(s0.peers[0].public_key, b_pub);

    // A port another link holds is refused with a readable reason.
    let mut clash = a.clone();
    clash.listen_port = 51821;
    let e = hal
        .wireguard_set(&n("wgt0"), &clash, &a_pub)
        .unwrap_err()
        .to_string();
    assert!(e.contains("port"), "{e}");

    // Taking the interfaces out of the config deletes the links.
    hal.apply(&cfg, &Config::default()).unwrap();
    assert!(!ip(&["-o", "link", "show"]).contains("wgt0"));
}

#[test]
fn a_link_that_is_not_ours_is_refused() {
    if !in_netns() {
        return;
    }
    let mut hal = LinuxHal::new();
    let (a_priv, a_pub) = alice();
    let dev = WgDevice {
        private_key: a_priv,
        listen_port: 51900,
        peers: Vec::new(),
    };
    // Made by someone else, absent from the config.
    ip(&["link", "add", "wgext", "type", "wireguard"]);
    let e = hal
        .wireguard_set(&n("wgext"), &dev, &a_pub)
        .unwrap_err()
        .to_string();
    assert!(
        e.contains("not a WireGuard interface of this router"),
        "{e}"
    );
    ip(&["link", "del", "wgext"]);
}

//! `l2` (LLDP over AF_PACKET, MNDP over UDP) against a real kernel, inside a
//! throwaway network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_l2
//! ```
//!
//! (`cargo xtask netns` runs it in its own namespace.) Same guard as
//! `tests/netns.rs`: without the variable every test is skipped, and with it
//! the tests refuse to run unless the namespace holds nothing but `lo`.
//! Each test uses its own veth pair; the two ends stand for two routers on
//! one cable. LLDPDUs are built by hand here (hal-linux, L1, cannot use
//! `proto-lldp`, L2): the bytes only have to survive the trip unchanged.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::{SocketAddr, UdpSocket};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use corerouter_hal_linux::l2::{LldpFrame, LldpIo, MndpListener, UdpDatagram};
use corerouter_model::IfName;

const ENV: &str = "COREROUTER_NETNS_TESTS";

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

/// A veth pair `a` <-> `b`, both up.
fn veth(a: &str, b: &str) {
    ip(&["link", "add", a, "type", "veth", "peer", "name", b]);
    ip(&["link", "set", a, "up"]);
    ip(&["link", "set", b, "up"]);
}

fn mac_of(name: &str) -> [u8; 6] {
    let out = ip(&["-o", "link", "show", "dev", name]);
    let hex = out
        .split_whitespace()
        .skip_while(|w| *w != "link/ether")
        .nth(1)
        .unwrap();
    let v: Vec<u8> = hex
        .split(':')
        .map(|h| u8::from_str_radix(h, 16).unwrap())
        .collect();
    v.try_into().unwrap()
}

fn allmulti(name: &str) -> bool {
    let out = ip(&["-o", "link", "show", "dev", name]);
    let flags = out.split('<').nth(1).unwrap().split('>').next().unwrap();
    flags.split(',').any(|f| f == "ALLMULTI")
}

/// Minimal LLDPDU, encoded by hand: Chassis ID (MAC), Port ID (interface
/// name), TTL 120, End.
fn lldpdu(mac: [u8; 6], port: &str) -> Vec<u8> {
    let tlv = |t: u16, v: &[u8]| {
        let h = (t << 9) | u16::try_from(v.len()).unwrap();
        [&h.to_be_bytes()[..], v].concat()
    };
    [
        tlv(1, &[&[4][..], &mac].concat()),
        tlv(2, &[&[5][..], port.as_bytes()].concat()),
        tlv(3, &120u16.to_be_bytes()),
        tlv(0, &[]),
    ]
    .concat()
}

fn wait_lldp(io: &mut LldpIo) -> Vec<LldpFrame> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let got = io.recv();
        if !got.is_empty() || Instant::now() > deadline {
            return got;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn lldp_frames_cross_a_veth_pair_both_ways() {
    if !in_netns() {
        return;
    }
    veth("lldpa", "lldpb");
    let mut a = LldpIo::new(Duration::from_secs(30));
    let mut b = LldpIo::new(Duration::from_secs(30));
    assert!(a.set_interfaces(&[n("lldpa")]).is_empty());
    assert!(b.set_interfaces(&[n("lldpb")]).is_empty());
    let mac_a = mac_of("lldpa");
    let mac_b = mac_of("lldpb");
    assert_eq!(a.interfaces(), [(n("lldpa"), mac_a)]);

    // Never sent: due now; after a send, due again only one interval later.
    let t0 = Instant::now();
    assert_eq!(a.due(t0), [n("lldpa")]);
    let pdu_a = lldpdu(mac_a, "lldpa");
    a.send(&n("lldpa"), &pdu_a, t0).unwrap();
    assert!(a.due(t0 + Duration::from_secs(29)).is_empty());
    assert_eq!(a.due(t0 + Duration::from_secs(30)), [n("lldpa")]);

    let got = wait_lldp(&mut b);
    assert_eq!(got.len(), 1, "{got:?}");
    let f = got.first().unwrap();
    assert_eq!(f.interface, n("lldpb"));
    assert_eq!(f.src_mac, mac_a);
    // Short PDUs are zero-padded to the Ethernet minimum, after End.
    assert!(f.lldpdu.starts_with(&pdu_a), "{:?}", f.lldpdu);
    assert!(f.lldpdu.get(pdu_a.len()..).unwrap().iter().all(|&x| x == 0));
    // The sender does not hear its own frame.
    assert!(a.recv().is_empty());

    let pdu_b = lldpdu(mac_b, "lldpb");
    b.send(&n("lldpb"), &pdu_b, Instant::now()).unwrap();
    let got = wait_lldp(&mut a);
    assert_eq!(got.len(), 1, "{got:?}");
    assert_eq!(got.first().unwrap().src_mac, mac_b);
    assert!(got.first().unwrap().lldpdu.starts_with(&pdu_b));
}

#[test]
fn lldp_port_turns_allmulticast_on_and_back_off() {
    if !in_netns() {
        return;
    }
    veth("lldpc", "lldpd");
    assert!(!allmulti("lldpc"));
    let mut io = LldpIo::new(Duration::from_secs(30));
    assert!(io.set_interfaces(&[n("lldpc")]).is_empty());
    assert!(allmulti("lldpc"), "the LLDP group must pass the NIC filter");
    assert!(io.set_interfaces(&[]).is_empty());
    assert!(!allmulti("lldpc"), "closing the port restores the flag");

    // Already on (someone else's choice): left on when we close.
    ip(&["link", "set", "lldpc", "allmulticast", "on"]);
    assert!(io.set_interfaces(&[n("lldpc")]).is_empty());
    drop(io);
    assert!(allmulti("lldpc"));
}

#[test]
fn lldp_reports_interfaces_it_cannot_open() {
    if !in_netns() {
        return;
    }
    veth("lldpe", "lldpf");
    let mut io = LldpIo::new(Duration::from_secs(30));
    let failed = io.set_interfaces(&[n("lldpe"), n("nosuch0")]);
    assert_eq!(failed.len(), 1);
    assert_eq!(failed.first().unwrap().0, n("nosuch0"));
    assert_eq!(io.interfaces().len(), 1);
    assert!(
        io.send(&n("nosuch0"), &[0; 10], Instant::now()).is_err(),
        "not open"
    );
}

#[test]
fn mndp_listener_gets_broadcasts_with_the_arrival_interface() {
    if !in_netns() {
        return;
    }
    veth("mndpa", "mndpb");
    ip(&["addr", "add", "10.56.0.1/24", "dev", "mndpa"]);
    ip(&["addr", "add", "10.56.0.2/24", "dev", "mndpb"]);
    // Both ends live in one namespace, so the source is a local address and
    // the kernel would drop the copy arriving on mndpb as martian. This
    // sysctl only exists inside the throwaway namespace.
    for (knob, v) in [("accept_local", "1"), ("rp_filter", "0")] {
        std::fs::write(format!("/proc/sys/net/ipv4/conf/mndpb/{knob}"), v).unwrap();
    }
    let mut l = MndpListener::bind(0).unwrap();
    let port = l.local_port().unwrap();

    let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None).unwrap();
    s.set_broadcast(true).unwrap();
    s.bind_device(Some(b"mndpa")).unwrap();
    s.bind(&SocketAddr::from(([10, 56, 0, 1], 0)).into())
        .unwrap();
    let s: UdpSocket = s.into();
    s.send_to(b"\0\0\0\x01announce", ("10.56.0.255", port))
        .unwrap();

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut got: Vec<UdpDatagram> = Vec::new();
    while Instant::now() < deadline && !got.iter().any(|d| d.interface == Some(n("mndpb"))) {
        got.extend(l.recv());
        std::thread::sleep(Duration::from_millis(20));
    }
    let d = got
        .iter()
        .find(|d| d.interface == Some(n("mndpb")))
        .unwrap_or_else(|| panic!("no datagram on mndpb: {got:?}"));
    assert_eq!(d.payload, b"\0\0\0\x01announce");
    assert_eq!(
        d.src,
        SocketAddr::from(([10, 56, 0, 1], s.local_addr().unwrap().port()))
    );
}

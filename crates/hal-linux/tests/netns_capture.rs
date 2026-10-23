//! Packet capture (`capture.rs`, G6.4a) against a real kernel, inside a
//! throwaway network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_capture
//! ```
//!
//! Same guard as `tests/netns.rs`. Each test makes its own veth pair
//! (`<p>a` ── `<p>b`, both ends here) and writes frames into `<p>a` with a
//! packet socket of its own; the capture listens on `<p>b` (received) or
//! `<p>a` (sent). The root of the user namespace has `CAP_NET_RAW` there.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use corerouter_hal::capture::{
    CaptureDevice, CaptureSocket, CaptureSpec, Dir, FrameBatch, HEADERS_SNAPLEN, PacketCapture,
    decode,
};
use corerouter_hal_linux::capture::HostCapture;
use nix::ifaddrs::getifaddrs;
use nix::sys::socket::{LinkAddr, bind};
use socket2::{Domain, Protocol, Socket, Type};

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
        if names != ["lo"] {
            return Err(format!(
                "{ENV}=1 but this network namespace has {names:?}, not just lo; refusing to \
                 touch it (run inside `unshare --user --map-root-user --net`)"
            ));
        }
        Ok(())
    });
    if let Err(e) = fresh {
        panic!("{e}");
    }
    true
}

fn ip(args: &[&str]) {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A veth pair `<p>a` ── `<p>b`, up.
fn veth(p: &str) -> (String, String) {
    let (a, b) = (format!("{p}a"), format!("{p}b"));
    ip(&["link", "add", &a, "type", "veth", "peer", "name", &b]);
    ip(&["link", "set", &a, "up"]);
    ip(&["link", "set", &b, "up"]);
    (a, b)
}

fn link_addr(name: &str) -> LinkAddr {
    getifaddrs()
        .unwrap()
        .filter(|a| a.interface_name == name)
        .find_map(|a| a.address.and_then(|s| s.as_link_addr().copied()))
        .unwrap()
}

/// A packet socket that writes raw frames into `dev`.
fn writer(dev: &str) -> Socket {
    let s = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0))).unwrap();
    bind(s.as_raw_fd(), &link_addr(dev)).unwrap();
    s
}

/// An IPv4/UDP frame from 10.0.0.1:1000+i to 10.0.0.2:53, tagged with
/// `vlan` when given, `size` bytes long.
fn udp_frame(i: u16, vlan: Option<u16>, size: usize) -> Vec<u8> {
    let mut f = vec![0x02, 0, 0, 0, 0, 0xBB, 0x02, 0, 0, 0, 0, 0xAA];
    if let Some(v) = vlan {
        f.extend_from_slice(&[0x81, 0x00]);
        f.extend_from_slice(&v.to_be_bytes());
    }
    f.extend_from_slice(&[0x08, 0x00, 0x45, 0, 0, 28, 0, 0, 0, 0, 64, 17, 0, 0]);
    f.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
    f.extend_from_slice(&(1000 + i).to_be_bytes());
    f.extend_from_slice(&[0, 53, 0, 8, 0, 0]);
    f.resize(size.max(f.len()), 0);
    f
}

fn spec(devices: &[(&str, Option<u16>)], sample: u32) -> CaptureSpec {
    CaptureSpec {
        devices: devices
            .iter()
            .map(|(n, v)| CaptureDevice {
                name: (*n).into(),
                vlan: *v,
            })
            .collect(),
        snaplen: HEADERS_SNAPLEN,
        sample,
    }
}

/// Read everything that arrives until nothing has for 200 ms.
fn collect(sock: &mut Box<dyn CaptureSocket>) -> Vec<(Dir, Option<u16>, u32, Vec<u8>)> {
    let mut out = Vec::new();
    let mut batch = FrameBatch::new(4096);
    let mut quiet = Instant::now();
    while quiet.elapsed() < Duration::from_millis(200) {
        batch.clear();
        sock.recv(Duration::from_millis(50), &mut batch).unwrap();
        if !batch.is_empty() {
            quiet = Instant::now();
        }
        for (m, d) in batch.iter() {
            out.push((m.dir, m.vlan, m.wire_len, d.to_vec()));
        }
    }
    out
}

#[test]
fn frames_both_ways_with_their_wire_length() {
    if !in_netns() {
        return;
    }
    let (a, b) = veth("cap1");
    let mut rx = HostCapture.open(&spec(&[(&b, None)], 1)).unwrap();
    let mut tx = HostCapture.open(&spec(&[(&a, None)], 1)).unwrap();
    let w = writer(&a);
    for i in 0..50 {
        w.send(&udp_frame(i, None, 1000)).unwrap();
    }
    let got = collect(&mut rx);
    let ours: Vec<_> = got
        .iter()
        .filter(|(_, _, _, d)| decode(d).is_some_and(|x| x.dst_port == Some(53)))
        .collect();
    assert_eq!(ours.len(), 50, "{} frames in all", got.len());
    assert!(ours.iter().all(|(dir, vlan, len, d)| *dir == Dir::Rx
        && vlan.is_none()
        && *len == 1000
        && d.len() == usize::from(HEADERS_SNAPLEN)));
    let sent = collect(&mut tx);
    let ours = sent
        .iter()
        .filter(|(dir, _, _, d)| {
            *dir == Dir::Tx && decode(d).is_some_and(|x| x.dst_port == Some(53))
        })
        .count();
    assert_eq!(ours, 50);
    let t = rx.totals().unwrap();
    assert!(t.rx_packets >= 50, "{t:?}");
}

#[test]
fn kernel_sampling_keeps_about_one_in_n() {
    if !in_netns() {
        return;
    }
    let (a, b) = veth("cap2");
    let mut rx = HostCapture.open(&spec(&[(&b, None)], 1)).unwrap();
    rx.set_sampling(10).unwrap();
    let w = writer(&a);
    let n = 20_000u16;
    for i in 0..n {
        w.send(&udp_frame(i, None, 64)).unwrap();
        if i % 500 == 0 {
            // Let the receive buffer drain now and then.
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    let kept = collect(&mut rx)
        .iter()
        .filter(|(_, _, _, d)| decode(d).is_some_and(|x| x.dst_port == Some(53)))
        .count();
    // Binomial(20000, 0.1): mean 2000, sd ~42; ±300 is > 7 sd.
    assert!((1700..=2300).contains(&kept), "kept {kept}");
}

#[test]
fn vlans_are_counted_once_on_their_device() {
    if !in_netns() {
        return;
    }
    let (a, b) = veth("cap3");
    let sub = format!("{b}.100");
    ip(&[
        "link", "add", "link", &b, "name", &sub, "type", "vlan", "id", "100",
    ]);
    ip(&["link", "set", &sub, "up"]);
    let mut rx = HostCapture
        .open(&spec(&[(&b, None), (&sub, Some(100))], 1))
        .unwrap();
    let w = writer(&a);
    for i in 0..30 {
        w.send(&udp_frame(i, Some(100), 200)).unwrap();
        w.send(&udp_frame(i, None, 200)).unwrap();
    }
    let got: Vec<_> = collect(&mut rx)
        .into_iter()
        .filter(|(_, _, _, d)| decode(d).is_some_and(|x| x.dst_port == Some(53)))
        .collect();
    let tagged = got.iter().filter(|(_, v, _, _)| *v == Some(100)).count();
    let untagged = got.iter().filter(|(_, v, _, _)| v.is_none()).count();
    assert_eq!((tagged, untagged), (30, 30), "{got:?}");
    // Without its VLAN device, the parent keeps the tagged frames.
    let mut rx = HostCapture.open(&spec(&[(&b, None)], 1)).unwrap();
    for i in 0..10 {
        w.send(&udp_frame(i, Some(100), 200)).unwrap();
    }
    let n = collect(&mut rx)
        .iter()
        .filter(|(_, _, _, d)| decode(d).is_some_and(|x| x.dst_port == Some(53)))
        .count();
    assert_eq!(n, 10);
}

#[test]
fn unknown_interface_is_refused() {
    if !in_netns() {
        return;
    }
    let e = HostCapture
        .open(&spec(&[("nope0", None)], 1))
        .err()
        .unwrap();
    assert!(e.to_string().contains("nope0"), "{e}");
}

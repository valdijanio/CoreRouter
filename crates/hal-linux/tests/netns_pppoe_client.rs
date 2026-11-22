//! G3.9ga: the PPPoE client's relay (`pppoe_client_io`) against a real
//! kernel, inside a throwaway network namespace — no root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_pppoe_client -- --nocapture
//! ```
//!
//! ```text
//!   kernel ── pppoe-out1 ═ veth ═ pppoe-out1-r ── relay ── u0 ═ veth ═ u1 (the "BNG")
//! ```
//!
//! What the kernel routes out of `pppoe-out1` leaves `u0` as PPPoE session
//! frames of the session; the BNG's frames of the session reach a socket
//! bound on `pppoe-out1`'s address; control frames go to the engine's
//! queue and data of another session nowhere; the MSS of a TCP SYN is
//! lowered both ways. Last, the relay's packet rate one way and the other
//! is printed (**medido** in `docs/pppoe-client.md`).
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::{TcpStream, UdpSocket};
use std::process::Command;
use std::time::{Duration, Instant};

use corerouter_hal::pppoe_client::{PppoeClientPort, SessionLink};
use corerouter_hal_linux::pppoe_client_io::LinuxPppoeClientPort;
use corerouter_hal_linux::pppoe_io::PppoePort;
use corerouter_model::IfName;

const ENV: &str = "COREROUTER_NETNS_TESTS";
const SID: u16 = 0x1234;
/// How long each direction is flooded for the packet rate.
const FLOOD_MS: u64 = 500;

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
        .map(|n| n.trim().split('@').next().unwrap_or(""))
        .collect();
    assert_eq!(
        names,
        ["lo"],
        "{ENV}=1 but this namespace has {names:?}; refusing to touch it"
    );
    true
}

fn ip(args: &[&str]) {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "ip {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// MAC of `dev` (sysfs shows the host's namespace here: ask `ip`).
fn mac(dev: &str) -> [u8; 6] {
    let out = Command::new("ip")
        .args(["-o", "link", "show", "dev", dev])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let hex = text
        .split("link/ether ")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap()
        .to_owned();
    let mut m = [0u8; 6];
    for (i, p) in hex.split(':').enumerate() {
        m[i] = u8::from_str_radix(p, 16).unwrap();
    }
    m
}

/// Packets `dev` received (`/proc/net/dev` follows the namespace).
fn rx_packets(dev: &str) -> u64 {
    let text = std::fs::read_to_string("/proc/net/dev").unwrap();
    text.lines()
        .find_map(|l| l.trim().strip_prefix(&format!("{dev}:")))
        .and_then(|rest| rest.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap()
}

fn n(s: &str) -> IfName {
    s.parse().unwrap()
}

fn csum(parts: &[&[u8]]) -> u16 {
    let mut s: u32 = 0;
    for p in parts {
        for c in p.chunks(2) {
            s += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
        }
    }
    while s > 0xffff {
        s = (s & 0xffff) + (s >> 16);
    }
    !(s as u16)
}

/// IPv4 + `l4` (protocol `proto`) from `src` to `dst`, checksums right.
fn ipv4(src: [u8; 4], dst: [u8; 4], proto: u8, mut l4: Vec<u8>) -> Vec<u8> {
    let tot = 20 + l4.len();
    let mut p = vec![
        0x45,
        0,
        (tot >> 8) as u8,
        tot as u8,
        0,
        0,
        0x40,
        0,
        64,
        proto,
        0,
        0,
    ];
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    let c = csum(&[&p]);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    let pseudo = [
        &src[..],
        &dst[..],
        &[0, proto],
        &(l4.len() as u16).to_be_bytes()[..],
    ]
    .concat();
    let at = if proto == 17 { 6 } else { 16 };
    let c = csum(&[&pseudo, &l4]);
    l4[at..at + 2].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(&l4);
    p
}

fn udp(sport: u16, dport: u16, body: &[u8]) -> Vec<u8> {
    let mut u = Vec::new();
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + body.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(body);
    u
}

fn session_frame(dst: [u8; 6], src: [u8; 6], sid: u16, proto: u16, body: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&[0x88, 0x64, 0x11, 0x00]);
    f.extend_from_slice(&sid.to_be_bytes());
    f.extend_from_slice(&((body.len() + 2) as u16).to_be_bytes());
    f.extend_from_slice(&proto.to_be_bytes());
    f.extend_from_slice(body);
    f
}

/// Frames the BNG side read within `ms` that `keep` accepts.
fn bng_reads(bng: &mut PppoePort, ms: u64, mut keep: impl FnMut(&[u8]) -> bool) -> Vec<Vec<u8>> {
    let mut got = Vec::new();
    let t = Instant::now();
    while t.elapsed() < Duration::from_millis(ms) {
        bng.recv(|f| {
            if keep(f) {
                got.push(f.to_vec());
            }
        })
        .unwrap();
        if !got.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    got
}

/// MSS option of the TCP SYN in session frame `f`, if it is one.
fn syn_mss(f: &[u8]) -> Option<u16> {
    let ip = f.get(22..)?;
    if ip.first()? >> 4 != 4 || *ip.get(9)? != 6 {
        return None;
    }
    let tcp = ip.get(usize::from(ip[0] & 0x0f) * 4..)?;
    if tcp.get(13)? & 0x02 == 0 {
        return None;
    }
    let hdr = usize::from(tcp[12] >> 4) * 4;
    let mut i = 20;
    while i + 3 < hdr {
        match tcp[i] {
            0 => return None,
            1 => i += 1,
            2 => return Some(u16::from_be_bytes([tcp[i + 2], tcp[i + 3]])),
            _ => i += usize::from(tcp[i + 1]).max(2),
        }
    }
    None
}

#[test]
fn relay_carries_the_session_both_ways() {
    if !in_netns() {
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "add", "u0", "type", "veth", "peer", "name", "u1"]);
    ip(&["link", "set", "u0", "up"]);
    ip(&["link", "set", "u1", "up"]);
    ip(&[
        "link",
        "add",
        "pppoe-out1",
        "type",
        "veth",
        "peer",
        "name",
        "pppoe-out1-r",
    ]);
    ip(&[
        "link",
        "set",
        "pppoe-out1",
        "arp",
        "off",
        "mtu",
        "1460",
        "up",
    ]);
    ip(&["link", "set", "pppoe-out1-r", "arp", "off", "up"]);
    ip(&[
        "addr",
        "add",
        "10.9.0.1",
        "peer",
        "10.9.0.2",
        "dev",
        "pppoe-out1",
    ]);
    let (m0, m1, mo) = (mac("u0"), mac("u1"), mac("pppoe-out1"));

    let mut port = LinuxPppoeClientPort::open(&n("pppoe-out1"), "pppoe-out1-r", &n("u0")).unwrap();
    assert_eq!(port.mac(), m0);
    let mut bng = PppoePort::open(&n("u1"), &[], true).unwrap();

    // Control: a Discovery frame (a PADO) reaches the engine's queue; a
    // data frame without a session reaches nothing.
    let mut pado = Vec::new();
    pado.extend_from_slice(&m0);
    pado.extend_from_slice(&m1);
    pado.extend_from_slice(&[0x88, 0x63, 0x11, 0x07, 0, 0, 0, 0]);
    bng.send(&pado).unwrap();
    let data = session_frame(
        m0,
        m1,
        SID,
        0x0021,
        &ipv4([10, 9, 0, 2], [10, 9, 0, 1], 17, udp(1, 9001, b"x")),
    );
    bng.send(&data).unwrap();
    let t = Instant::now();
    let mut control = Vec::new();
    while t.elapsed() < Duration::from_secs(2) && control.is_empty() {
        if let Some(f) = port.recv().unwrap() {
            control.push(f);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(control, vec![pado], "the PADO, and only it");
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(port.recv().unwrap(), None, "data never goes to the engine");

    port.set_session(Some(SessionLink {
        session_id: SID,
        ac_mac: m1,
        clamp_mtu: Some(1400),
    }))
    .unwrap();

    // Kernel → wire.
    let s = UdpSocket::bind("10.9.0.1:0").unwrap();
    s.send_to(b"hello bng", "10.9.0.2:9000").unwrap();
    let got = bng_reads(&mut bng, 2000, |f| {
        f.len() > 22 && f[12..14] == [0x88, 0x64] && f[20..22] == [0, 0x21]
    });
    let f = got.first().expect("an IPv4 session frame on u1");
    assert_eq!(&f[..6], &m1, "to the AC");
    assert_eq!(&f[6..12], &m0, "from the port");
    assert_eq!(&f[14..16], &[0x11, 0x00]);
    assert_eq!(u16::from_be_bytes([f[16], f[17]]), SID);
    assert_eq!(
        usize::from(u16::from_be_bytes([f[18], f[19]])),
        f.len() - 20
    );
    assert!(f.ends_with(b"hello bng"));

    // Wire → kernel.
    let r = UdpSocket::bind("10.9.0.1:9001").unwrap();
    r.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    bng.send(&session_frame(
        m0,
        m1,
        SID,
        0x0021,
        &ipv4(
            [10, 9, 0, 2],
            [10, 9, 0, 1],
            17,
            udp(5, 9001, b"from the bng"),
        ),
    ))
    .unwrap();
    let mut buf = [0u8; 64];
    let (len, from) = r
        .recv_from(&mut buf)
        .expect("the BNG's datagram on pppoe-out1");
    assert_eq!(&buf[..len], b"from the bng");
    assert_eq!(from.to_string(), "10.9.0.2:5");
    // Another session's data: dropped, never delivered.
    bng.send(&session_frame(
        m0,
        m1,
        0x9999,
        0x0021,
        &ipv4([10, 9, 0, 2], [10, 9, 0, 1], 17, udp(5, 9001, b"stale")),
    ))
    .unwrap();
    r.set_read_timeout(Some(Duration::from_millis(300)))
        .unwrap();
    assert!(
        r.recv_from(&mut buf).is_err(),
        "another session's data reached the kernel"
    );

    // MSS: the kernel's SYN says 1420 (mtu 1460); the relay lowers it to
    // 1360 (clamp_mtu 1400 − 40).
    let _ = TcpStream::connect_timeout(&"10.9.0.2:80".parse().unwrap(), Duration::from_millis(300));
    let got = bng_reads(&mut bng, 2000, |f| syn_mss(f).is_some());
    assert_eq!(got.first().and_then(|f| syn_mss(f)), Some(1360));
    assert!(port.counters().mss_clamped >= 1);

    // The relay's packet rate (not a pass/fail: the CI machine varies).
    for (name, size) in [("64 B", 64usize), ("1400 B", 1400)] {
        let before = rx_packets("u1");
        let t = Instant::now();
        let body = vec![0u8; size];
        let mut sent = 0u64;
        while t.elapsed() < Duration::from_millis(FLOOD_MS) {
            if s.send_to(&body, "10.9.0.2:9000").is_ok() {
                sent += 1;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
        let out = rx_packets("u1") - before;
        eprintln!(
            "relay kernel→wire {name}: {:.0} pps relayed ({:.0} pps offered)",
            out as f64 * 1000.0 / FLOOD_MS as f64,
            sent as f64 * 1000.0 / FLOOD_MS as f64
        );
        let frame = session_frame(
            m0,
            m1,
            SID,
            0x0021,
            &ipv4([10, 9, 0, 2], [10, 9, 0, 1], 17, udp(5, 9002, &body)),
        );
        let before = rx_packets("pppoe-out1");
        let t = Instant::now();
        let mut sent = 0u64;
        while t.elapsed() < Duration::from_millis(FLOOD_MS) {
            if bng.send(&frame).is_ok() {
                sent += 1;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
        let inn = rx_packets("pppoe-out1") - before;
        eprintln!(
            "relay wire→kernel {name}: {:.0} pps relayed ({:.0} pps offered)",
            inn as f64 * 1000.0 / FLOOD_MS as f64,
            sent as f64 * 1000.0 / FLOOD_MS as f64
        );
    }
    let c = port.counters();
    assert!(c.tx_packets > 1 && c.rx_packets > 1, "{c:?}");
    drop(port);
    let _ = mo;
}

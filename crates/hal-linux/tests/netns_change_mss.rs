//! G1.31d — `action=change-mss` against a real kernel, in a throwaway
//! network namespace (no root, nothing reaches the host):
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_change_mss
//! ```
//!
//! A TCP SYN written with `AF_PACKET` into veth `ca` comes in on its peer
//! `cb`, is routed (`ip_forward`) and leaves by veth `sa` (MTU 1400) towards
//! `sb`, where a packet socket reads it back. The mangle rule the firewall
//! loads changes the MSS option on the way; the test reads the option and
//! checks the TCP checksum the kernel fixed (`inet_proto_csum_replace2`):
//!
//! - no rule: the SYN keeps its 1460;
//! - `clamp-to-pmtu` in forward: 1400 − 40 = 1360 (IPv4), 1400 − 60 = 1340
//!   (IPv6), the route's MTU (`NFT_RT_TCPMSS`);
//! - a SYN that already carries less keeps it (the kernel never raises it);
//! - an ACK carrying the option is left alone (`tcp-flags=syn`);
//! - a fixed `new-mss=1300` in prerouting, before routing.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::process::Command;
use std::time::{Duration, Instant};

use corerouter_firewall::sample::{act, m, rule};
use corerouter_hal_linux::{firewall, nft};
use corerouter_model::Config;
use corerouter_model::cow_list::CowList;
use nix::ifaddrs::getifaddrs;
use nix::sys::socket::{LinkAddr, MsgFlags, bind, recv, send};
use socket2::{Domain, Protocol, Socket, Type};

const ENV: &str = "COREROUTER_NETNS_TESTS";

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
    if !nft::available() {
        eprintln!("skipped: the `nft` program (nftables) is not installed");
        return false;
    }
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

fn sysctl(path: &str, v: &str) {
    std::fs::write(format!("/proc/sys/{path}"), v).unwrap_or_else(|e| panic!("{path}: {e}"));
}

fn link(name: &str) -> (LinkAddr, [u8; 6]) {
    getifaddrs()
        .unwrap()
        .filter(|a| a.interface_name == name)
        .find_map(|a| {
            let l = *a.address?.as_link_addr()?;
            Some((l, l.addr()?))
        })
        .unwrap()
}

fn sum16(data: &[u8]) -> u32 {
    data.chunks(2)
        .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
        .sum()
}

fn fold(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The TCP checksum of `tcp` between `src` and `dst` (RFC 9293 §3.1,
/// RFC 8200 §8.1): 0 when `tcp` already holds a right one.
fn tcp_sum(src: IpAddr, dst: IpAddr, tcp: &[u8]) -> u16 {
    let mut pseudo = Vec::new();
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            pseudo.extend_from_slice(&s.octets());
            pseudo.extend_from_slice(&d.octets());
            pseudo.extend_from_slice(&[0, 6]);
            pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            pseudo.extend_from_slice(&s.octets());
            pseudo.extend_from_slice(&d.octets());
            pseudo.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 6]);
        }
        _ => panic!("one family for both addresses"),
    }
    fold(sum16(&pseudo) + sum16(tcp))
}

/// TCP header with the MSS option (and a NOP pair, as Linux pads it).
fn tcp(sport: u16, flags: u8, mss: u16) -> Vec<u8> {
    let mut t = Vec::new();
    t.extend_from_slice(&sport.to_be_bytes());
    t.extend_from_slice(&80u16.to_be_bytes());
    t.extend_from_slice(&1000u32.to_be_bytes());
    t.extend_from_slice(&0u32.to_be_bytes());
    t.push(6 << 4); // 24 bytes: 20 + the 4 of the option
    t.push(flags);
    t.extend_from_slice(&64240u16.to_be_bytes());
    t.extend_from_slice(&[0, 0, 0, 0]); // checksum, urgent pointer
    t.extend_from_slice(&[2, 4]);
    t.extend_from_slice(&mss.to_be_bytes());
    t
}

/// An Ethernet frame with an IPv4 or IPv6 packet carrying `segment`.
fn frame(
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
    src: IpAddr,
    dst: IpAddr,
    mut seg: Vec<u8>,
) -> Vec<u8> {
    let c = tcp_sum(src, dst, &seg);
    seg[16..18].copy_from_slice(&c.to_be_bytes());
    let mut f = Vec::new();
    f.extend_from_slice(&dst_mac);
    f.extend_from_slice(&src_mac);
    match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            f.extend_from_slice(&[0x08, 0x00]);
            let mut h = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0];
            h[2..4].copy_from_slice(&((20 + seg.len()) as u16).to_be_bytes());
            h.extend_from_slice(&s.octets());
            h.extend_from_slice(&d.octets());
            let c = fold(sum16(&h));
            h[10..12].copy_from_slice(&c.to_be_bytes());
            f.extend_from_slice(&h);
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            f.extend_from_slice(&[0x86, 0xdd]);
            f.extend_from_slice(&[0x60, 0, 0, 0]);
            f.extend_from_slice(&(seg.len() as u16).to_be_bytes());
            f.extend_from_slice(&[6, 64]);
            f.extend_from_slice(&s.octets());
            f.extend_from_slice(&d.octets());
        }
        _ => panic!("one family for both addresses"),
    }
    f.extend_from_slice(&seg);
    f
}

/// A segment read back: its source, destination and TCP bytes.
type Seen<'a> = (IpAddr, IpAddr, &'a [u8]);

/// What came out of `sb` for source port `sport`: its MSS option, and
/// whether its checksum is right.
fn read_mss(sock: &Socket, sport: u16) -> Option<(u16, bool)> {
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut buf = [0u8; 2048];
    while Instant::now() < deadline {
        let Ok(n) = recv(sock.as_raw_fd(), &mut buf, MsgFlags::MSG_DONTWAIT) else {
            std::thread::sleep(Duration::from_millis(5));
            continue;
        };
        let f = &buf[..n];
        let (src, dst, seg): Seen<'_> = match (f[12], f[13]) {
            (0x08, 0x00) if f[23] == 6 => {
                let ihl = usize::from(f[14] & 0x0f) * 4;
                let s: [u8; 4] = f[26..30].try_into().unwrap();
                let d: [u8; 4] = f[30..34].try_into().unwrap();
                let total = usize::from(u16::from_be_bytes([f[16], f[17]]));
                (s.into(), d.into(), &f[14 + ihl..14 + total])
            }
            (0x86, 0xdd) if f[20] == 6 => {
                let s: [u8; 16] = f[22..38].try_into().unwrap();
                let d: [u8; 16] = f[38..54].try_into().unwrap();
                let len = usize::from(u16::from_be_bytes([f[18], f[19]]));
                (s.into(), d.into(), &f[54..54 + len])
            }
            _ => continue,
        };
        if u16::from_be_bytes([seg[0], seg[1]]) != sport {
            continue;
        }
        let mss = u16::from_be_bytes([seg[22], seg[23]]);
        return Some((mss, tcp_sum(src, dst, seg) == 0));
    }
    None
}

struct Lab {
    inject: Socket,
    capture: Socket,
    ca_mac: [u8; 6],
    cb_mac: [u8; 6],
    sport: u16,
}

impl Lab {
    fn new() -> Self {
        sysctl("net/ipv4/ip_forward", "1");
        sysctl("net/ipv4/conf/all/rp_filter", "0");
        sysctl("net/ipv6/conf/all/forwarding", "1");
        ip(&["link", "add", "ca", "type", "veth", "peer", "name", "cb"]);
        ip(&["link", "add", "sa", "type", "veth", "peer", "name", "sb"]);
        ip(&["link", "set", "sa", "mtu", "1400"]);
        ip(&["link", "set", "sb", "mtu", "1400"]);
        for d in ["ca", "cb", "sa", "sb"] {
            ip(&["link", "set", d, "up"]);
        }
        sysctl("net/ipv4/conf/cb/rp_filter", "0");
        ip(&["addr", "add", "10.7.0.1/24", "dev", "cb"]);
        ip(&["addr", "add", "10.8.0.1/24", "dev", "sa"]);
        ip(&["-6", "addr", "add", "fd07::1/64", "dev", "cb", "nodad"]);
        ip(&["-6", "addr", "add", "fd08::1/64", "dev", "sa", "nodad"]);
        let (_, sb_mac) = link("sb");
        let mac = sb_mac
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        ip(&["neigh", "add", "10.8.0.2", "lladdr", &mac, "dev", "sa"]);
        ip(&["-6", "neigh", "add", "fd08::2", "lladdr", &mac, "dev", "sa"]);
        let (ca, ca_mac) = link("ca");
        let (sb, _) = link("sb");
        let (_, cb_mac) = link("cb");
        let inject = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0))).unwrap();
        bind(inject.as_raw_fd(), &ca).unwrap();
        let all = Protocol::from(i32::from(0x0003u16.to_be()));
        let capture = Socket::new(Domain::PACKET, Type::RAW, Some(all)).unwrap();
        bind(capture.as_raw_fd(), &sb).unwrap();
        Lab {
            inject,
            capture,
            ca_mac,
            cb_mac,
            sport: 40000,
        }
    }

    /// Send one segment from the client side; the MSS it left with.
    fn through(&mut self, v6: bool, flags: u8, mss: u16) -> (u16, bool) {
        self.sport += 1;
        let (src, dst): (IpAddr, IpAddr) = if v6 {
            ("fd07::2".parse().unwrap(), "fd08::2".parse().unwrap())
        } else {
            ("10.7.0.2".parse().unwrap(), "10.8.0.2".parse().unwrap())
        };
        let f = frame(
            self.cb_mac,
            self.ca_mac,
            src,
            dst,
            tcp(self.sport, flags, mss),
        );
        send(self.inject.as_raw_fd(), &f, MsgFlags::empty()).unwrap();
        read_mss(&self.capture, self.sport)
            .unwrap_or_else(|| panic!("segment {} (v6 {v6}) never left by sa", self.sport))
    }
}

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;

/// A mangle rule: chain, matchers, action JSON.
type MangleRule<'a> = (&'a str, &'a [(&'a str, &'a str)], &'a str);

fn with_mangle(rules: &[MangleRule<'_>]) -> Config {
    let mut c = Config::default();
    let list: Vec<_> = rules
        .iter()
        .enumerate()
        .map(|(i, (chain, pairs, a))| {
            rule(i as u32 + 1, chain, m(pairs).unwrap(), act(a).unwrap()).unwrap()
        })
        .collect();
    c.ip.firewall.next_rule_id = list.len() as u32 + 1;
    c.ip.firewall.mangle = CowList::from(list);
    c
}

#[test]
fn a_forwarded_syn_gets_its_mss_lowered() {
    if !ready() {
        return;
    }
    let mut lab = Lab::new();
    // No rule: as sent.
    assert_eq!(lab.through(false, SYN, 1460), (1460, true));
    assert_eq!(lab.through(true, SYN, 1440), (1440, true));

    let empty = Config::default();
    let clamp = with_mangle(&[(
        "forward",
        &[("protocol", "tcp"), ("tcp_flags", "syn")],
        r#"{"type": "change-mss", "new_mss": "clamp-to-pmtu"}"#,
    )]);
    firewall::apply(&empty, &clamp).unwrap();
    // RFC 9293 §3.7.1: MTU − 20 (IPv4) − 20 (TCP); RFC 8200: − 40 − 20.
    assert_eq!(lab.through(false, SYN, 1460), (1360, true));
    assert_eq!(lab.through(true, SYN, 1440), (1340, true));
    // SYN-ACK too (tcp-flags=syn does not say !ack).
    assert_eq!(lab.through(false, SYN | ACK, 1460), (1360, true));
    // Never raised.
    assert_eq!(lab.through(false, SYN, 1200), (1200, true));
    // Not a SYN: left alone.
    assert_eq!(lab.through(false, ACK, 1460), (1460, true));

    // tcp-flags=syn,!ack: the client's SYN only.
    let only_syn = with_mangle(&[(
        "forward",
        &[("protocol", "tcp"), ("tcp_flags", "syn,!ack")],
        r#"{"type": "change-mss", "new_mss": "clamp-to-pmtu"}"#,
    )]);
    firewall::apply(&clamp, &only_syn).unwrap();
    assert_eq!(lab.through(false, SYN, 1460), (1360, true));
    assert_eq!(lab.through(false, SYN | ACK, 1460), (1460, true));

    // A fixed value before routing; the first rule passes it on and a
    // second, lower one in forward still applies.
    let fixed = with_mangle(&[
        (
            "prerouting",
            &[("protocol", "tcp"), ("tcp_flags", "syn")],
            r#"{"type": "change-mss", "new_mss": "1300"}"#,
        ),
        (
            "forward",
            &[
                ("protocol", "tcp"),
                ("tcp_flags", "syn"),
                ("out_interface", "sa"),
            ],
            r#"{"type": "change-mss", "new_mss": "1250"}"#,
        ),
    ]);
    firewall::apply(&only_syn, &fixed).unwrap();
    assert_eq!(lab.through(false, SYN, 1460), (1250, true));
    assert_eq!(lab.through(true, SYN, 1440), (1250, true));
    firewall::remove().unwrap();
    assert_eq!(lab.through(false, SYN, 1460), (1460, true));
}

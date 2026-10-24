//! G2.5a: the XDP filter loaded for real. Needs root (CAP_BPF and
//! CAP_NET_ADMIN in the initial user namespace), so it runs only where
//! `COREROUTER_XDP_ROOT=1`: `cargo xtask xdp-root` sets it on the CI runner
//! (a throwaway VM), inside a throwaway named network namespace; elsewhere
//! every test returns at once. Nothing here touches the host's links: the
//! veth pairs live in that namespace and in a second one this test makes.
//!
//! 1. The verifier accepts the program; it attaches native and generic.
//! 2. Differential: thousands of generated, cut and corrupted frames go
//!    through the kernel program (`BPF_PROG_TEST_RUN`) and through the
//!    host's `decide` with the same lists; the verdicts must match.
//! 3. Real traffic (ping from a peer namespace): pass/blocked/rate-limit
//!    counters, the top-sources table, the allow list winning.
//! 4. Measured (printed as `PERF |` lines): ns per packet in the kernel by
//!    block-trie size (the cost per LPM entry), time to load N prefixes,
//!    and a userspace sender over veth: no filter, nftables raw drop, XDP drop.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![cfg(target_os = "linux")]

use std::process::Command;
use std::time::{Duration, Instant};

use corerouter_dataplane_ebpf_common::filter::{Settings, decide};
use corerouter_dataplane_ebpf_common::parse::{Addr, IPPROTO_UDP};
use corerouter_dataplane_ebpf_common::testing::{Model, Spec, build, spec};
use corerouter_hal::xdp::XdpStatus;
use corerouter_hal_linux::xdp::{NatFlow, XdpState};
use corerouter_model::firewall::{AddrMatch, AddressListEntry};
use corerouter_model::xdp::{XdpInterface, XdpMode};
use corerouter_model::{Config, IfName, Interface, InterfaceKind, ItemId};
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::TestRunner;

const XDP_DROP: u32 = 1;
const XDP_PASS: u32 = 2;
const PEER_NS: &str = "crxdpb";

fn enabled() -> bool {
    std::env::var_os("COREROUTER_XDP_ROOT").is_some_and(|v| v == "1")
}

fn sh(args: &[&str]) -> String {
    let out = Command::new(args[0]).args(&args[1..]).output().unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn sh_ok(args: &[&str]) -> bool {
    Command::new(args[0])
        .args(&args[1..])
        .output()
        .is_ok_and(|o| o.status.success())
}

/// veth `xa` here (10.99.0.1/24) ↔ `xb` in namespace `crxdpb` (10.99.0.2/24).
struct Pair;

impl Pair {
    fn new() -> Self {
        let _ = sh_ok(&["ip", "netns", "del", PEER_NS]);
        let _ = sh_ok(&["ip", "link", "del", "xa"]);
        sh(&["ip", "netns", "add", PEER_NS]);
        sh(&[
            "ip", "link", "add", "xa", "type", "veth", "peer", "name", "xb",
        ]);
        sh(&["ip", "link", "set", "xb", "netns", PEER_NS]);
        sh(&["ip", "addr", "add", "10.99.0.1/24", "dev", "xa"]);
        sh(&["ip", "link", "set", "xa", "up"]);
        sh(&["ip", "link", "set", "lo", "up"]);
        let peer = |a: &[&str]| {
            let mut v = vec!["ip", "netns", "exec", PEER_NS];
            v.extend_from_slice(a);
            sh(&v)
        };
        peer(&["ip", "addr", "add", "10.99.0.2/24", "dev", "xb"]);
        peer(&["ip", "link", "set", "xb", "up"]);
        peer(&["ip", "link", "set", "lo", "up"]);
        Pair
    }

    /// `ping` from the peer: how many replies came back.
    fn ping(&self, count: u32, flood: bool) -> u32 {
        let c = count.to_string();
        let mut args = vec![
            "ip", "netns", "exec", PEER_NS, "ping", "-n", "-q", "-c", &c, "-W", "1",
        ];
        if flood {
            args.push("-f");
        } else {
            args.extend(["-i", "0.01"]);
        }
        args.push("10.99.0.1");
        let out = Command::new(args[0]).args(&args[1..]).output().unwrap();
        let text = String::from_utf8_lossy(&out.stdout);
        // "20 packets transmitted, 18 received, …"
        text.split(',')
            .find_map(|p| p.trim().strip_suffix(" received"))
            .and_then(|n| n.trim().parse().ok())
            .unwrap_or(0)
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        let _ = sh_ok(&["ip", "link", "del", "xa"]);
        let _ = sh_ok(&["ip", "netns", "del", PEER_NS]);
    }
}

fn xa() -> IfName {
    "xa".parse().unwrap()
}

/// A config with XDP on `xa` in `mode`, block list `bad` and allow list
/// `ok` holding `block` and `allow`.
fn config(mode: XdpMode, block: &[&str], allow: &[&str]) -> Config {
    let mut cfg = Config::default();
    cfg.interfaces
        .insert(xa(), Interface::new(xa(), InterfaceKind::Ethernet));
    let fw = &mut cfg.ip.firewall;
    for (i, (list, a)) in block
        .iter()
        .map(|a| ("bad", a))
        .chain(allow.iter().map(|a| ("ok", a)))
        .enumerate()
    {
        fw.address_lists.push(AddressListEntry {
            id: ItemId(i as u32 + 1),
            list: list.parse().unwrap(),
            address: AddrMatch::Net(a.parse().unwrap()),
            disabled: false,
            comment: String::new(),
        });
    }
    let x = &mut cfg.ip.xdp;
    x.interfaces.push(XdpInterface {
        interface: xa(),
        mode,
        disabled: false,
        comment: String::new(),
    });
    x.filter.block_lists = vec!["bad".parse().unwrap()];
    x.filter.allow_lists = vec!["ok".parse().unwrap()];
    cfg
}

fn port(st: &XdpStatus) -> &corerouter_hal::xdp::XdpPort {
    st.ports
        .iter()
        .find(|p| p.interface == xa())
        .expect("xa attached")
}

#[test]
fn loads_attaches_and_counts() {
    if !enabled() {
        return;
    }
    let pair = Pair::new();
    let mut x = XdpState::default();

    // 1. Verifier + both modes.
    x.sync(&config(XdpMode::Native, &[], &[])).unwrap();
    assert_eq!(port(&x.status(0)).active, Some("native"));
    x.sync(&config(XdpMode::Generic, &[], &[])).unwrap();
    assert_eq!(port(&x.status(0)).active, Some("generic"));
    x.sync(&config(XdpMode::Auto, &[], &[])).unwrap();
    let st = x.status(0);
    println!("auto on veth: {:?} {:?}", port(&st).active, port(&st).note);

    // 3. Traffic: everything passes.
    assert!(pair.ping(20, false) >= 18, "ping through the filter");
    let pass = port(&x.status(0)).counters[0].0;
    assert!(pass >= 20, "pass counter {pass}");

    // Block the peer: no replies, blocked counter, top source.
    x.sync(&config(XdpMode::Auto, &["10.99.0.0/24"], &[]))
        .unwrap();
    assert_eq!(pair.ping(10, false), 0, "blocked peer still answered");
    let st = x.status(10);
    assert!(port(&st).counters[1].0 >= 10, "{:?}", port(&st).counters);
    let top = st.top.first().expect("a top source");
    assert_eq!(top.address.to_string(), "10.99.0.2");
    assert_eq!(top.reason, "blocked");
    assert_eq!(top.list.as_ref().map(|l| l.as_str()), Some("bad"));
    assert_eq!(st.block_prefixes, 1);

    // The allow list wins.
    x.sync(&config(XdpMode::Auto, &["10.99.0.0/24"], &["10.99.0.2/32"]))
        .unwrap();
    assert!(pair.ping(10, false) >= 9, "allowed peer");

    // Rate limit: 10 pps, burst 5, a flood of 300.
    let mut cfg = config(XdpMode::Auto, &[], &[]);
    cfg.ip.xdp.filter.rate_limit = 10;
    cfg.ip.xdp.filter.rate_burst = 5;
    x.sync(&cfg).unwrap();
    x.reset().unwrap();
    let got = pair.ping(300, true);
    let limited = port(&x.status(0)).counters[2].0;
    println!("flood of 300 at 10 pps: {got} replies, {limited} rate-limited");
    assert!(
        got < 100 && limited > 150,
        "{got} replies, {limited} limited"
    );

    // Off: everything detached and unloaded.
    x.sync(&Config::default()).unwrap();
    assert!(x.status(0).ports.is_empty());
    assert!(pair.ping(5, false) >= 4);
}

/// Differential (2): the kernel program and the host's `decide` agree on every frame.
#[test]
fn kernel_and_host_agree() {
    if !enabled() {
        return;
    }
    let _pair = Pair::new();
    let mut runner = TestRunner::deterministic();
    // Lists from generated addresses, so frames hit them.
    let nets: Vec<(Addr, u32)> = (0..40)
        .map(|_| {
            let s = spec().new_tree(&mut runner).unwrap().current();
            let len = match s.src {
                Addr::V4(_) => 8 + (s.sport as u32 % 25),
                Addr::V6(_) => 16 + (s.sport as u32 % 113),
            };
            (s.src, len)
        })
        .collect();
    let text = |(a, len): &(Addr, u32)| match a {
        Addr::V4(b) => format!("{}/{len}", std::net::Ipv4Addr::from(*b)),
        Addr::V6(b) => format!("{}/{len}", std::net::Ipv6Addr::from(*b)),
    };
    let block: Vec<String> = nets[..30].iter().map(text).collect();
    let allow: Vec<String> = nets[30..].iter().map(text).collect();
    let b: Vec<&str> = block.iter().map(String::as_str).collect();
    let a: Vec<&str> = allow.iter().map(String::as_str).collect();
    let mut x = XdpState::default();
    x.sync(&config(XdpMode::Generic, &b, &a)).unwrap();
    let mut model = Model {
        block: nets[..30].iter().map(|(n, l)| (*n, *l, 0)).collect(),
        allow: nets[30..].to_vec(),
        ..Model::default()
    };
    let settings = Settings {
        drop_malformed: true,
        drop_bad_tcp_flags: true,
        block: true,
        allow: true,
        rate_pps: 0,
        burst: 0,
        fast_nat: false,
    };
    let mut checked = 0;
    let mut drops = 0;
    for i in 0..4000u32 {
        let s = spec().new_tree(&mut runner).unwrap().current();
        let mut s = s;
        // Half the frames from a listed network.
        if i % 2 == 0 {
            s.src = nets[(i as usize / 2) % nets.len()].0;
            if matches!(s.src, Addr::V6(_)) != matches!(s.dst, Addr::V6(_)) {
                s.dst = s.src;
            }
        }
        let mut f = build(&s);
        match i % 4 {
            // Cut somewhere.
            1 => f.truncate(14 + (i as usize * 7) % f.len().max(15)),
            // Corrupt a header byte.
            2 => {
                let at = 12 + (i as usize * 13) % (f.len() - 12);
                f[at] ^= 1 << (i % 8);
            }
            _ => {}
        }
        if f.len() < 14 {
            continue; // BPF_PROG_TEST_RUN wants a whole Ethernet header.
        }
        let (action, _) = x.test_run(&f, 1).unwrap();
        let want = decide(&f[..], &settings, &mut model, 0);
        let got_drop = action == XDP_DROP;
        assert!(
            action == XDP_DROP || action == XDP_PASS,
            "action {action} for {f:02x?}"
        );
        assert_eq!(
            got_drop, want.drop,
            "frame {i} {f:02x?}: kernel {action}, host {want:?}"
        );
        checked += 1;
        drops += usize::from(got_drop);
    }
    println!("kernel and host agree on {checked} frames ({drops} dropped)");
    assert!(checked > 3500 && drops > 200, "{checked} {drops}");
}

fn udp4(src: [u8; 4]) -> Vec<u8> {
    build(&Spec {
        vlans: vec![],
        src: Addr::V4(src),
        dst: Addr::V4([10, 99, 0, 1]),
        proto: IPPROTO_UDP,
        sport: 4000,
        dport: 53,
        flags: 0,
        payload: 18,
    })
}

/// Measured (4): kernel ns per packet by trie size, and the time to load
/// the prefixes.
#[test]
fn perf_lpm_cost() {
    if !enabled() {
        return;
    }
    let _pair = Pair::new();
    println!("PERF | prefixes | load ms | pass ns/pkt | blocked ns/pkt | rate-limited pass ns/pkt");
    for n in [0usize, 1_000, 10_000, 100_000, 1_000_000] {
        // n distinct /32s in 100.64.0.0/10 (never the test frames' 192.0.2.1).
        let nets: Vec<String> = (0..n)
            .map(|i| {
                let v = (100u32 << 24 | 64 << 16) + i as u32;
                format!("{}/32", std::net::Ipv4Addr::from(v))
            })
            .collect();
        let refs: Vec<&str> = nets.iter().map(String::as_str).collect();
        let mut cfg = config(XdpMode::Generic, &refs, &[]);
        let mut x = XdpState::default();
        let t = Instant::now();
        x.sync(&cfg).unwrap();
        let load = t.elapsed();
        let reps = 2_000_000;
        let pass = x.test_run(&udp4([192, 0, 2, 1]), reps).unwrap();
        let blocked = if n > 0 {
            x.test_run(&udp4([100, 64, 0, 7]), reps).unwrap()
        } else {
            (XDP_PASS, Duration::ZERO)
        };
        assert_eq!(pass.0, XDP_PASS);
        assert!(n == 0 || blocked.0 == XDP_DROP);
        cfg.ip.xdp.filter.rate_limit = 100_000_000;
        x.sync(&cfg).unwrap();
        let limited = x.test_run(&udp4([192, 0, 2, 1]), reps).unwrap();
        println!(
            "PERF | {n} | {} | {} | {} | {}",
            load.as_millis(),
            pass.1.as_nanos(),
            blocked.1.as_nanos(),
            limited.1.as_nanos()
        );
    }
}

/// Measured (4): a userspace sender blasting 64-byte UDP frames from
/// random sources in 198.18.0.0/15 out of `yb` into its veth peer `ya`
/// (both here), for two seconds per case: no filter (the kernel stack
/// drops them), an nftables raw-table drop of those sources (the kernel
/// path the Firewall uses), and XDP drop by block list, generic and native.
/// The sender and the receive side share one core for the stack and generic
/// cases (veth hands the frame over in the sender's softirq), so the send
/// rate is what the receive cost allows; native veth XDP runs in the
/// peer's NAPI instead. It compares costs; it is not a NIC's line rate.
/// (pktgen hung the CI VM even with a reset: never again.)
#[test]
fn perf_veth_blast() {
    if !enabled() {
        return;
    }
    let _ = sh_ok(&["ip", "link", "del", "ya"]);
    sh(&[
        "ip", "link", "add", "ya", "type", "veth", "peer", "name", "yb",
    ]);
    sh(&["ip", "addr", "add", "10.98.0.1/24", "dev", "ya"]);
    sh(&["ip", "link", "set", "ya", "up"]);
    sh(&["ip", "link", "set", "yb", "up"]);
    let mac: Vec<u8> = sh(&["cat", "/sys/class/net/ya/address"])
        .trim()
        .split(':')
        .filter_map(|h| u8::from_str_radix(h, 16).ok())
        .collect();
    let frames: Vec<Vec<u8>> = (0..1024u32)
        .map(|i| {
            let mut f = udp4([198, 18 + (i >> 16) as u8 % 2, (i >> 8) as u8, i as u8]);
            f[..6].copy_from_slice(&mac);
            f[30..34].copy_from_slice(&[10, 98, 0, 1]);
            // A valid IPv4 header checksum: the stack drops bad ones in
            // ip_rcv, before nftables would see them.
            let sum = f[14..34]
                .chunks(2)
                .map(|w| u32::from(u16::from_be_bytes([w[0], w[1]])))
                .sum::<u32>();
            let sum = (sum & 0xffff) + (sum >> 16);
            let sum = (sum & 0xffff) + (sum >> 16);
            f[24..26].copy_from_slice(&(!(sum as u16)).to_be_bytes());
            f
        })
        .collect();
    let sock = socket2::Socket::new(socket2::Domain::PACKET, socket2::Type::RAW, None).unwrap();
    let link = nix::ifaddrs::getifaddrs()
        .unwrap()
        .find(|a| {
            a.interface_name == "yb" && a.address.as_ref().and_then(|x| x.as_link_addr()).is_some()
        })
        .and_then(|a| a.address.and_then(|x| x.as_link_addr().copied()))
        .expect("yb link address");
    nix::sys::socket::bind(std::os::fd::AsRawFd::as_raw_fd(&sock), &link).unwrap();
    let blast = |secs: f64| -> u64 {
        let t = Instant::now();
        let mut sent = 0u64;
        while t.elapsed().as_secs_f64() < secs {
            for f in &frames {
                if nix::sys::socket::send(
                    std::os::fd::AsRawFd::as_raw_fd(&sock),
                    f,
                    nix::sys::socket::MsgFlags::empty(),
                )
                .is_ok()
                {
                    sent += 1;
                }
            }
        }
        sent
    };
    let rx = || -> u64 {
        sh(&["cat", "/sys/class/net/ya/statistics/rx_packets"])
            .trim()
            .parse()
            .unwrap_or(0)
    };
    let secs = 2.0;
    let report = |label: &str, sent: u64, seen: u64| {
        println!(
            "PERF | veth blast | {label} | {:.0} kpps sent | {seen} handled of {sent}",
            sent as f64 / secs / 1000.0
        );
    };
    let r0 = rx();
    let sent = blast(secs);
    report("no filter (kernel stack)", sent, rx().saturating_sub(r0));
    if sh_ok(&["nft", "--version"]) {
        sh(&["nft", "add table inet crxdp"]);
        sh(&[
            "nft",
            "add chain inet crxdp raw { type filter hook prerouting priority -300; }",
        ]);
        sh(&[
            "nft",
            "add rule inet crxdp raw ip saddr 198.18.0.0/15 counter drop",
        ]);
        let sent = blast(secs);
        let out = sh(&["nft", "list chain inet crxdp raw"]);
        let seen = out
            .split("packets ")
            .nth(1)
            .and_then(|t| t.split_whitespace().next())
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        report("nftables raw drop", sent, seen);
        sh(&["nft", "delete table inet crxdp"]);
    }
    let ya: IfName = "ya".parse().unwrap();
    for mode in [XdpMode::Generic, XdpMode::Native] {
        let mut cfg = config(mode, &["198.18.0.0/15"], &[]);
        cfg.interfaces.insert(
            ya.clone(),
            Interface::new(ya.clone(), InterfaceKind::Ethernet),
        );
        cfg.ip.xdp.interfaces[0].interface = ya.clone();
        let mut x = XdpState::default();
        x.sync(&cfg).unwrap();
        let blocked = |x: &mut XdpState| {
            x.status(0)
                .ports
                .iter()
                .find(|p| p.interface == ya)
                .map_or(0, |p| p.counters[1].0)
        };
        let before = blocked(&mut x);
        let sent = blast(secs);
        let seen = blocked(&mut x).saturating_sub(before);
        report(&format!("XDP {} drop", mode.name()), sent, seen);
        x.sync(&Config::default()).unwrap();
    }
    let _ = sh_ok(&["ip", "link", "del", "ya"]);
}

/// The router of the fast-NAT tests: this namespace, with `la`
/// (100.64.0.1/24) to subscriber namespace `crxsub` (100.64.0.2) and `wa`
/// (198.51.100.1/24) to internet namespace `crxinet` (198.51.100.2).
struct Triangle;

const SUB_NS: &str = "crxsub";
const INET_NS: &str = "crxinet";

impl Triangle {
    fn new() -> Self {
        for ns in [SUB_NS, INET_NS] {
            let _ = sh_ok(&["ip", "netns", "del", ns]);
            sh(&["ip", "netns", "add", ns]);
        }
        for (here, there, ns, me, peer) in [
            ("la", "lb", SUB_NS, "100.64.0.1/24", "100.64.0.2/24"),
            ("wa", "wb", INET_NS, "198.51.100.1/24", "198.51.100.2/24"),
        ] {
            let _ = sh_ok(&["ip", "link", "del", here]);
            sh(&[
                "ip", "link", "add", here, "type", "veth", "peer", "name", there,
            ]);
            sh(&["ip", "link", "set", there, "netns", ns]);
            sh(&["ip", "addr", "add", me, "dev", here]);
            sh(&["ip", "link", "set", here, "up"]);
            for a in [
                vec!["ip", "addr", "add", peer, "dev", there],
                vec!["ip", "link", "set", there, "up"],
                vec!["ip", "link", "set", "lo", "up"],
            ] {
                let mut v = vec!["ip", "netns", "exec", ns];
                v.extend(a);
                sh(&v);
            }
        }
        sh(&[
            "ip",
            "netns",
            "exec",
            SUB_NS,
            "ip",
            "route",
            "add",
            "default",
            "via",
            "100.64.0.1",
        ]);
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
        // Neighbors both ways, so the FIB lookup finds them.
        for (ns, to) in [(SUB_NS, "100.64.0.1"), (INET_NS, "198.51.100.1")] {
            sh(&["ip", "netns", "exec", ns, "ping", "-c", "1", "-W", "2", to]);
        }
        for to in ["100.64.0.2", "198.51.100.2"] {
            sh(&["ping", "-c", "1", "-W", "2", to]);
        }
        Triangle
    }

    /// Run `f` on a thread inside namespace `ns`.
    fn spawn_in<T: Send + 'static>(
        ns: &str,
        f: impl FnOnce() -> T + Send + 'static,
    ) -> std::thread::JoinHandle<T> {
        let path = format!("/run/netns/{ns}");
        std::thread::spawn(move || {
            let fd = std::fs::File::open(&path).unwrap();
            nix::sched::setns(fd, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
            f()
        })
    }
}

impl Drop for Triangle {
    fn drop(&mut self) {
        for l in ["la", "wa"] {
            let _ = sh_ok(&["ip", "link", "del", l]);
        }
        for ns in [SUB_NS, INET_NS] {
            let _ = sh_ok(&["ip", "netns", "del", ns]);
        }
    }
}

fn ifindex(name: &str) -> u32 {
    sh(&["cat", &format!("/sys/class/net/{name}/ifindex")])
        .trim()
        .parse()
        .unwrap()
}

/// XDP (generic) on `la` and `wa` with the CGNAT fast path on, and the two
/// directions of one NATed UDP "connection" installed by hand:
/// 100.64.0.2:5000 → 198.51.100.2:7 leaves as 198.51.100.1:20000.
fn fast_nat_router() -> (XdpState, [NatFlow; 2]) {
    let mut cfg = Config::default();
    for n in ["la", "wa"] {
        let name: IfName = n.parse().unwrap();
        cfg.interfaces.insert(
            name.clone(),
            Interface::new(name.clone(), InterfaceKind::Ethernet),
        );
        cfg.ip.xdp.interfaces.push(XdpInterface {
            interface: name,
            mode: XdpMode::Generic,
            disabled: false,
            comment: String::new(),
        });
    }
    cfg.ip.xdp.fast_nat = true;
    let mut x = XdpState::default();
    x.sync(&cfg).unwrap();
    let ip = |s: &str| -> std::net::Ipv4Addr { s.parse().unwrap() };
    let flows = [
        NatFlow {
            proto: IPPROTO_UDP,
            src: (ip("100.64.0.2"), 5000),
            dst: (ip("198.51.100.2"), 7),
            new_src: (ip("198.51.100.1"), 20000),
            new_dst: (ip("198.51.100.2"), 7),
        },
        NatFlow {
            proto: IPPROTO_UDP,
            src: (ip("198.51.100.2"), 7),
            dst: (ip("198.51.100.1"), 20000),
            new_src: (ip("198.51.100.2"), 7),
            new_dst: (ip("100.64.0.2"), 5000),
        },
    ];
    x.nat_install(&flows).unwrap();
    (x, flows)
}

/// G2.5b: the fast path alone translates and forwards both directions —
/// the kernel has no NAT here, so a reply from 198.51.100.2:7 reaching the
/// subscriber can only be XDP's work.
#[test]
fn fast_nat_forwards_both_directions() {
    if !enabled() {
        return;
    }
    let _t = Triangle::new();
    let (mut x, flows) = fast_nat_router();
    let server = Triangle::spawn_in(INET_NS, || {
        let s = std::net::UdpSocket::bind("198.51.100.2:7").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = s.recv_from(&mut buf).unwrap();
        s.send_to(&buf[..n], from).unwrap();
        from
    });
    std::thread::sleep(Duration::from_millis(200));
    let client = Triangle::spawn_in(SUB_NS, || {
        let s = std::net::UdpSocket::bind("100.64.0.2:5000").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        s.send_to(b"through xdp", "198.51.100.2:7").unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = s.recv_from(&mut buf).unwrap();
        (buf[..n].to_vec(), from)
    });
    let seen_by_server = server.join().unwrap();
    let (echo, from) = client.join().unwrap();
    assert_eq!(seen_by_server.to_string(), "198.51.100.1:20000");
    assert_eq!(echo, b"through xdp");
    assert_eq!(from.to_string(), "198.51.100.2:7");
    for f in &flows {
        let u = x.nat_use(f).unwrap().unwrap();
        assert!(u.packets >= 1 && u.last_ns > 0, "{f:?}: {u:?}");
    }
    let st = x.status(0);
    for p in &st.ports {
        println!("{}: {:?}", p.interface, p.counters);
        assert!(
            p.counters[corerouter_hal::xdp::FAST_NAT].0 >= 1,
            "{}",
            p.interface
        );
    }
    assert_eq!(x.nat_count(), 2);
    x.nat_remove(&flows).unwrap();
    assert_eq!(x.nat_count(), 0);
}

/// Measured: the fast path's cost in the kernel (FIB lookup, rewrite,
/// redirect) by `BPF_PROG_TEST_RUN` on `la`, against the filter's plain
/// pass.
#[test]
fn perf_fast_nat() {
    if !enabled() {
        return;
    }
    let _t = Triangle::new();
    let (mut x, _flows) = fast_nat_router();
    let mut f = build(&Spec {
        vlans: vec![],
        src: Addr::V4([100, 64, 0, 2]),
        dst: Addr::V4([198, 51, 100, 2]),
        proto: IPPROTO_UDP,
        sport: 5000,
        dport: 7,
        flags: 0,
        payload: 18,
    });
    f[22] = 64;
    let la = ifindex("la");
    let reps = 2_000_000;
    let (action, nat) = x.test_run_on(&f, reps, Some(la)).unwrap();
    assert_eq!(action, 4, "XDP_REDIRECT");
    let other = {
        let mut g = f.clone();
        g[37] = 8; // another destination port: no flow
        g
    };
    let (action, plain) = x.test_run_on(&other, reps, Some(la)).unwrap();
    assert_eq!(action, XDP_PASS);
    println!(
        "PERF | fast-nat | redirect ns/pkt {} | no flow (pass) ns/pkt {}",
        nat.as_nanos(),
        plain.as_nanos()
    );
}

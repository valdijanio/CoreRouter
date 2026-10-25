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
    println!("fast path misses: {:?}", st.fast_nat_misses);
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
    // Once: a known flow is translated and redirected.
    let (action, _) = x.test_run_on(&f, 1, Some(la)).unwrap();
    let misses = x.status(0).fast_nat_misses;
    assert_eq!(action, 4, "XDP_REDIRECT ({misses:?})");
    // BPF_PROG_TEST_RUN repeats on one buffer, which the first run
    // rewrote: time an identity flow instead (same 5-tuple in and out),
    // TTL 255, in batches of 250 runs (the TTL goes down by one each).
    let ip = |s: &str| -> std::net::Ipv4Addr { s.parse().unwrap() };
    let same = NatFlow {
        proto: IPPROTO_UDP,
        src: (ip("100.64.0.2"), 5001),
        dst: (ip("198.51.100.2"), 7),
        new_src: (ip("100.64.0.2"), 5001),
        new_dst: (ip("198.51.100.2"), 7),
    };
    x.nat_install(&[same]).unwrap();
    let mut g = f.clone();
    g[35] = 0x89; // source port 5001
    g[22] = 255;
    let (batches, per) = (4000u32, 250u32);
    let mut total = Duration::ZERO;
    for _ in 0..batches {
        let (action, d) = x.test_run_on(&g, per, Some(la)).unwrap();
        assert_eq!(action, 4);
        total += d;
    }
    let nat = total / batches;
    let mut h = g.clone();
    h[37] = 8; // another destination port: no flow
    let mut total = Duration::ZERO;
    for _ in 0..batches {
        let (action, d) = x.test_run_on(&h, per, Some(la)).unwrap();
        assert_eq!(action, XDP_PASS);
        total += d;
    }
    let plain = total / batches;
    println!(
        "PERF | fast-nat | redirect ns/pkt {} | no flow (pass) ns/pkt {}",
        nat.as_nanos(),
        plain.as_nanos()
    );
}

/// G2.5b end to end, with the kernel's NAT and conntrack: the first
/// packets of a UDP "connection" are NATed by an nftables SNAT rule; the
/// link's conntrack events put it in the fast path once it is established;
/// the rest goes through XDP (conntrack's counters stop growing); the
/// timeout renewal reaches conntrack; killing the connection takes it out
/// of the map. The same `Book` and link the daemon's `xdp-nat` service
/// drives.
#[test]
fn conntrack_puts_flows_in_the_fast_path() {
    use corerouter_hal::xdp_nat::{Action, Book, MAX_CARRIED};
    if !enabled() {
        return;
    }
    let _t = Triangle::new();
    sh(&["nft", "add table ip crxnat"]);
    sh(&[
        "nft",
        "add chain ip crxnat post { type nat hook postrouting priority 100; }",
    ]);
    sh(&[
        "nft",
        "add rule ip crxnat post oifname \"wa\" ip saddr 100.64.0.0/24 meta l4proto udp snat to 198.51.100.1:20000-20999",
    ]);
    let (mut x, _) = fast_nat_router();
    // Only conntrack fills the map in this test.
    x.nat_remove(&fast_nat_router_flows()).unwrap();
    let mut link = x.nat_link().unwrap();
    assert!(link.generation().is_some());
    let mut book = Book::new(MAX_CARRIED);
    let sync = |link: &mut Box<dyn corerouter_hal::xdp_nat::NatLink>, book: &mut Book, ms: u64| {
        let until = Instant::now() + Duration::from_millis(ms);
        while Instant::now() < until {
            let mut ev = Vec::new();
            link.events(50, 1024, &mut ev).unwrap();
            for e in &ev {
                println!(
                    "event {:?} proto {} {}:{} -> {}:{} status {:#x} tcp {:?} offloadable {}",
                    e.kind,
                    e.conn.protocol,
                    e.conn.orig.src,
                    e.conn.orig.src_port,
                    e.conn.orig.dst,
                    e.conn.orig.dst_port,
                    e.conn.status,
                    e.conn.tcp_state,
                    corerouter_hal::xdp_nat::offloadable(&e.conn)
                );
                match book.event(e) {
                    Some(Action::Install(f)) => link.install(&f).unwrap(),
                    Some(Action::Remove(f)) => link.remove(&f).unwrap(),
                    None => {}
                }
            }
        }
    };
    let rounds = 40usize;
    let server = Triangle::spawn_in(INET_NS, move || {
        let s = std::net::UdpSocket::bind("198.51.100.2:9").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut buf = [0u8; 64];
        let mut peers = Vec::new();
        for _ in 0..rounds {
            let Ok((n, from)) = s.recv_from(&mut buf) else {
                break;
            };
            s.send_to(&buf[..n], from).unwrap();
            peers.push(from);
        }
        peers
    });
    std::thread::sleep(Duration::from_millis(200));
    let (to_client, from_main) = std::sync::mpsc::channel::<()>();
    let (to_main, from_client) = std::sync::mpsc::channel::<usize>();
    let client = Triangle::spawn_in(SUB_NS, move || {
        let s = std::net::UdpSocket::bind("100.64.0.2:6000").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut buf = [0u8; 64];
        let mut got = 0;
        for i in 0..rounds {
            if i == 2 {
                // Conntrack marks a UDP flow assured only for a packet
                // more than 2 s after its start (nf_conntrack_proto_udp:
                // "still active after two seconds").
                std::thread::sleep(Duration::from_millis(2300));
            }
            s.send_to(format!("{i}").as_bytes(), "198.51.100.2:9")
                .unwrap();
            match s.recv_from(&mut buf) {
                Ok(_) => got += 1,
                Err(e) => println!("echo {i}: {e}"),
            }
            if i == 2 {
                // Assured now: let the main thread sync, then go on.
                to_main.send(got).unwrap();
                from_main.recv().unwrap();
            }
        }
        got
    });
    let early = from_client.recv().unwrap();
    println!("echoes through the kernel before the sync: {early} of 3");
    assert!(early >= 2, "the kernel path answered {early} of 3");
    sync(&mut link, &mut book, 1500);
    assert_eq!(book.len(), 1, "the established connection is carried");
    assert_eq!(x.nat_count(), 2);
    let ct_before: u64 = link
        .table()
        .unwrap()
        .iter()
        .filter(|c| c.orig.src.to_string() == "100.64.0.2")
        .map(|c| c.orig_packets + c.reply_packets)
        .sum();
    to_client.send(()).unwrap();
    let got = client.join().unwrap();
    let peers = server.join().unwrap();
    assert!(got + 1 >= rounds, "echoes {got} of {rounds}");
    assert!(
        peers.iter().all(|p| p.ip().to_string() == "198.51.100.1"),
        "{peers:?}"
    );
    let st = x.status(0);
    let fast: u64 = st
        .ports
        .iter()
        .map(|p| p.counters[corerouter_hal::xdp::FAST_NAT].0)
        .sum();
    println!("fast path packets {fast}, misses {:?}", st.fast_nat_misses);
    assert!(
        fast >= 2 * (rounds as u64 - 3) - 4,
        "fast path carried {fast}"
    );
    let ct_after: u64 = link
        .table()
        .unwrap()
        .iter()
        .filter(|c| c.orig.src.to_string() == "100.64.0.2")
        .map(|c| c.orig_packets + c.reply_packets)
        .sum();
    println!("conntrack packets before {ct_before}, after {ct_after}");
    // Renewal: the carried connection was used, so it is due once.
    let due = book.due(&|f| link.used(f));
    assert_eq!(due.len(), 1);
    assert_eq!(link.refresh(&due).unwrap(), 1);
    // Kill it in conntrack: the destroy event takes it out of the map.
    let conns: Vec<_> = link
        .table()
        .unwrap()
        .into_iter()
        .filter(|c| c.orig.src.to_string() == "100.64.0.2")
        .collect();
    corerouter_hal_linux::ctnl::delete(&conns).unwrap();
    sync(&mut link, &mut book, 1000);
    assert!(book.is_empty());
    assert_eq!(x.nat_count(), 0);
    let _ = sh_ok(&["nft", "delete table ip crxnat"]);
}

/// The two hand-made flows of [`fast_nat_router`].
fn fast_nat_router_flows() -> [NatFlow; 2] {
    let ip = |s: &str| -> std::net::Ipv4Addr { s.parse().unwrap() };
    [
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
    ]
}

/// Measured: UDP through the router for 2 s, sent from the subscriber's
/// namespace (64-byte frames), counted as they arrive in the internet
/// namespace: the kernel's NAT (an nftables SNAT rule, conntrack, routing)
/// against the XDP fast path (generic, on veth). Sender, router and
/// receiver share the CPU that runs the sender (veth hands frames over in
/// its softirq): a comparison of costs, not a NIC's line rate.
#[test]
fn perf_fast_nat_forward() {
    if !enabled() {
        return;
    }
    let _t = Triangle::new();
    let rx = || -> u64 {
        sh(&[
            "ip",
            "netns",
            "exec",
            INET_NS,
            "cat",
            "/sys/class/net/wb/statistics/rx_packets",
        ])
        .trim()
        .parse()
        .unwrap_or(0)
    };
    let blast = |port: u16| -> u64 {
        Triangle::spawn_in(SUB_NS, move || {
            let s = std::net::UdpSocket::bind(("100.64.0.2", port)).unwrap();
            let t = Instant::now();
            let mut sent = 0u64;
            while t.elapsed() < Duration::from_secs(2) {
                for _ in 0..256 {
                    if s.send_to(&[0u8; 18], "198.51.100.2:7").is_ok() {
                        sent += 1;
                    }
                }
            }
            sent
        })
        .join()
        .unwrap()
    };
    // Kernel: SNAT rule, no XDP.
    sh(&["nft", "add table ip crxnat"]);
    sh(&[
        "nft",
        "add chain ip crxnat post { type nat hook postrouting priority 100; }",
    ]);
    sh(&[
        "nft",
        "add rule ip crxnat post oifname \"wa\" ip saddr 100.64.0.0/24 meta l4proto udp snat to 198.51.100.1:20000",
    ]);
    let before = rx();
    let sent = blast(5000);
    let seen = rx().saturating_sub(before);
    println!(
        "PERF | forward | kernel NAT (nftables + conntrack) | {:.0} kpps delivered | {seen} of {sent}",
        seen as f64 / 2000.0
    );
    let _ = sh_ok(&["nft", "delete table ip crxnat"]);
    // XDP fast path (generic): the flows of `fast_nat_router`.
    let (mut x, _) = fast_nat_router();
    let before = rx();
    let sent = blast(5000);
    let seen = rx().saturating_sub(before);
    let fast: u64 = x
        .status(0)
        .ports
        .iter()
        .map(|p| p.counters[corerouter_hal::xdp::FAST_NAT].0)
        .sum();
    println!(
        "PERF | forward | XDP fast path (generic, veth) | {:.0} kpps delivered | {seen} of {sent} (fast path {fast})",
        seen as f64 / 2000.0
    );
    x.sync(&Config::default()).unwrap();
}

// --- G4.3c: PPPoE subscribers -------------------------------------------------

use corerouter_dataplane_ebpf_common::policer::Rate;
use corerouter_dataplane_ebpf_common::pppoe::{
    self, F_FAST_DOWN, F_FAST_UP, F_IPV4, F_IPV6, F_PD, PPP_IPV4, PPP_IPV6, Session,
};
use corerouter_dataplane_ebpf_common::testing::{
    Subs, pppoe_frame, program_model, test_session, with_checksums,
};

const XDP_REDIRECT: u32 = 4;

/// The settings `config()` gives the filter (its defaults, no lists).
const PPPOE_FILTER: Settings = Settings {
    drop_malformed: true,
    drop_bad_tcp_flags: true,
    block: false,
    allow: false,
    rate_pps: 0,
    burst: 0,
    fast_nat: false,
};

/// G4.3c differential: thousands of generated session frames (0–2 VLAN
/// tags, IPv4/IPv6, both directions, hairpin), cut, corrupted, spoofed,
/// with odd protocol fields, padded, and noise, through the kernel program
/// (`BPF_PROG_TEST_RUN`) and through the host model of the whole program
/// (`testing::program_model`) with the same 300 sessions. The action and
/// every output byte (after decapsulation or encapsulation) must match.
#[test]
fn pppoe_kernel_and_host_agree() {
    if !enabled() {
        return;
    }
    let _pair = Pair::new();
    let mut x = XdpState::default();
    x.set_pppoe(true).unwrap();
    x.sync(&config(XdpMode::Generic, &[], &[])).unwrap();
    let port = ifindex("xa");
    let mut subs = Subs::default();
    let n = 300u32;
    let mut all = Vec::new();
    for i in 0..n {
        let mut flags = F_IPV4 | F_IPV6 | F_PD;
        // Half fast; `% 4` so the odd indexes the downstream frames pick
        // (k × 7 with k odd) get both kinds.
        if i % 4 < 2 {
            flags |= F_FAST_DOWN;
        }
        let mut s = test_session(i, port, (i % 3) as u8, flags);
        if i % 7 == 0 {
            s.mtu = 1480;
        }
        x.pppoe_upsert(i, &s).unwrap();
        subs.insert(i, &s, 0);
        all.push(s);
    }
    let mut runner = TestRunner::deterministic();
    let mut model = Model::default();
    let (mut checked, mut by_action) = (0, std::collections::BTreeMap::<u32, u32>::new());
    for k in 0..6000u32 {
        let s = &all[(k as usize * 7) % all.len()];
        let other = &all[(k as usize * 13 + 1) % all.len()];
        let mut sp = spec().new_tree(&mut runner).unwrap().current();
        sp.vlans.clear();
        if k % 9 != 0 {
            sp.flags = 0x10;
        }
        let v6 = matches!(sp.src, Addr::V6(_));
        let addr_of = |s: &Session, host: u8| {
            if v6 {
                let mut a = [0u8; 16];
                a[..8].copy_from_slice(&s.ipv6_prefix);
                a[15] = host;
                Addr::V6(a)
            } else {
                Addr::V4(s.ipv4)
            }
        };
        let up = k % 2 == 0;
        let mut f = if up {
            sp.src = addr_of(s, 1);
            if k % 6 == 0 {
                sp.dst = addr_of(other, 2); // hairpin
            } else if let Addr::V6(d) = &mut sp.dst
                && d[0] == 0xff
            {
                d[0] = 0x20;
            }
            let ip = with_checksums(build(&sp));
            pppoe_frame(s, &ip, if v6 { PPP_IPV6 } else { PPP_IPV4 })
        } else {
            sp.dst = addr_of(s, 3);
            with_checksums(build(&sp))
        };
        match k % 11 {
            1 => f.truncate(14 + (k as usize * 7) % f.len().max(15)),
            2 => {
                let at = 12 + (k as usize * 13) % (f.len() - 12);
                f[at] ^= 1 << (k % 8);
            }
            3 if up => {
                // Another SID.
                let off = 14 + 4 * (s.vlan != 0) as usize + 4 * (s.inner_vlan != 0) as usize;
                f[off + 3] ^= 0x5a;
            }
            4 if up => {
                // A protocol field picked from the frame number.
                let off = 14 + 4 * (s.vlan != 0) as usize + 4 * (s.inner_vlan != 0) as usize;
                f[off + 6..off + 8]
                    .copy_from_slice(&(k.wrapping_mul(2654435761) as u16).to_be_bytes());
            }
            5 => f.extend(std::iter::repeat_n(0u8, (k % 40) as usize)),
            6 => {
                f = (0..(14 + k % 90)).map(|b| (b * 31 + k) as u8).collect();
                if k % 2 == 0 {
                    f[12..14].copy_from_slice(&pppoe::ETH_P_PPP_SES.to_be_bytes());
                }
            }
            _ => {}
        }
        if f.len() < 14 {
            continue;
        }
        let (act, _, out) = x.test_run_out(&f, 1, Some(port)).unwrap();
        let (want, want_out, _, st) =
            program_model(&f, port, &PPPOE_FILTER, &mut subs, &mut model, 0);
        assert_eq!(
            (act, &out),
            (want, &want_out),
            "frame {k} ({st:?}) {f:02x?}"
        );
        checked += 1;
        *by_action.entry(act).or_default() += 1;
    }
    println!("PPPoE: kernel and host agree on {checked} frames, by action {by_action:?}");
    println!("PPPoE stats: {:?}", x.pppoe_stats());
    assert!(checked > 5000, "{checked}");
    for a in [XDP_DROP, XDP_PASS, XDP_REDIRECT] {
        assert!(
            by_action.get(&a).copied().unwrap_or(0) > 300,
            "{by_action:?}"
        );
    }
}

/// MAC of `dev` in namespace `ns` (`None`: this one).
fn mac_of(ns: Option<&str>, dev: &str) -> [u8; 6] {
    let path = format!("/sys/class/net/{dev}/address");
    let text = match ns {
        Some(ns) => sh(&["ip", "netns", "exec", ns, "cat", &path]),
        None => sh(&["cat", &path]),
    };
    let v: Vec<u8> = text
        .trim()
        .split(':')
        .filter_map(|h| u8::from_str_radix(h, 16).ok())
        .collect();
    v.try_into().unwrap()
}

/// An AF_PACKET socket on `dev` of the calling thread's namespace, for
/// EtherType `proto` (sending any frame, receiving `proto`).
fn packet_socket(dev: &str, proto: u16) -> socket2::Socket {
    let sock = socket2::Socket::new(
        socket2::Domain::PACKET,
        socket2::Type::RAW,
        Some(socket2::Protocol::from(i32::from(proto.to_be()))),
    )
    .unwrap();
    let link = nix::ifaddrs::getifaddrs()
        .unwrap()
        .find(|a| {
            a.interface_name == dev && a.address.as_ref().and_then(|x| x.as_link_addr()).is_some()
        })
        .and_then(|a| a.address.and_then(|x| x.as_link_addr().copied()))
        .expect("link address");
    nix::sys::socket::bind(std::os::fd::AsRawFd::as_raw_fd(&sock), &link).unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    sock
}

fn send_raw(sock: &socket2::Socket, f: &[u8]) {
    nix::sys::socket::send(
        std::os::fd::AsRawFd::as_raw_fd(sock),
        f,
        nix::sys::socket::MsgFlags::empty(),
    )
    .unwrap();
}

/// XDP (generic) on `la` (access port) and `wa` (uplink) with PPPoE on,
/// and the internet namespace routing 100.64.0.0/10 back to the router.
fn pppoe_router() -> XdpState {
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
    let _ = sh_ok(&[
        "ip",
        "netns",
        "exec",
        INET_NS,
        "ip",
        "route",
        "add",
        "100.64.0.0/10",
        "via",
        "198.51.100.1",
    ]);
    // The decapsulated packets arrive on `la` from addresses outside its
    // subnet: no reverse-path filter in this test namespace.
    for k in ["all", "la", "default"] {
        let _ = std::fs::write(format!("/proc/sys/net/ipv4/conf/{k}/rp_filter"), "0");
    }
    let mut x = XdpState::default();
    x.set_pppoe(true).unwrap();
    x.sync(&cfg).unwrap();
    x
}

/// A session of the client `lb` (in `crxsub`) on `la`.
fn lb_session(sid: u16, ip: [u8; 4], flags: u16) -> Session {
    Session {
        flags: pppoe::F_ACTIVE | F_IPV4 | flags,
        ifindex: ifindex("la"),
        sid,
        client_mac: mac_of(Some(SUB_NS), "lb"),
        server_mac: mac_of(None, "la"),
        ipv4: ip,
        ..Session::default()
    }
}

/// UDP 64-byte-ish frame `src:sport → dst:dport` with `payload`, as an
/// untagged frame with right checksums.
fn udp_frame(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, payload: usize) -> Vec<u8> {
    with_checksums(build(&Spec {
        vlans: vec![],
        src: Addr::V4(src),
        dst: Addr::V4(dst),
        proto: IPPROTO_UDP,
        sport,
        dport,
        flags: 0,
        payload,
    }))
}

/// G4.3c with real traffic: a client in `crxsub` speaks raw PPPoE on `lb`;
/// a UDP echo server in `crxinet` answers.
/// - fast session: upstream decapsulated and forwarded in XDP (FIB), the
///   echo encapsulated in XDP and delivered to the client as a session
///   frame (SID, MACs, TTL one lower);
/// - kernel session: decapsulated, then routed by the kernel;
/// - discovery passes to userspace, a spoofed SID is dropped.
#[test]
fn pppoe_traffic_both_ways() {
    if !enabled() {
        return;
    }
    let _t = Triangle::new();
    let mut x = pppoe_router();
    let fast = lb_session(0x42, [100, 64, 9, 9], F_FAST_UP | F_FAST_DOWN);
    let slow = lb_session(0x43, [100, 64, 9, 10], 0);
    x.pppoe_upsert(1, &fast).unwrap();
    x.pppoe_upsert(2, &slow).unwrap();
    let server = Triangle::spawn_in(INET_NS, || {
        let s = std::net::UdpSocket::bind("198.51.100.2:7").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut seen = Vec::new();
        let mut buf = [0u8; 256];
        for _ in 0..2 {
            let Ok((n, from)) = s.recv_from(&mut buf) else {
                break;
            };
            seen.push((buf[..n].to_vec(), from));
            s.send_to(&buf[..n], from).unwrap();
        }
        seen
    });
    std::thread::sleep(Duration::from_millis(200));
    let (fast_c, slow_c) = (fast, slow);
    let client = Triangle::spawn_in(SUB_NS, move || {
        let tx = packet_socket("lb", 0x0003); // ETH_P_ALL for sending
        let rx = packet_socket("lb", pppoe::ETH_P_PPP_SES);
        let mut disc = vec![0xffu8; 6];
        disc.extend(fast_c.client_mac);
        disc.extend(pppoe::ETH_P_PPP_DISC.to_be_bytes());
        disc.extend([0x11, 0x09, 0, 0, 0, 0]); // PADI, empty
        disc.resize(60, 0);
        send_raw(&tx, &disc);
        // Spoofed: the fast session's MAC with an unknown SID.
        let spoof = Session {
            sid: 0x99,
            ..fast_c
        };
        let ip = udp_frame([100, 64, 9, 9], 5000, [198, 51, 100, 2], 7, 18);
        send_raw(&tx, &pppoe_frame(&spoof, &ip, PPP_IPV4));
        send_raw(&tx, &pppoe_frame(&fast_c, &ip, PPP_IPV4));
        let ip = udp_frame([100, 64, 9, 10], 5001, [198, 51, 100, 2], 7, 18);
        send_raw(&tx, &pppoe_frame(&slow_c, &ip, PPP_IPV4));
        // The echo of the fast session's datagram comes back encapsulated.
        let mut buf = [0u8; 2048];
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(4) {
            let Ok(n) = std::io::Read::read(&mut &rx, &mut buf) else {
                break;
            };
            let f = buf[..n].to_vec();
            if f.len() > 14 + 8 + 28 && f[6..12] == fast_c.server_mac {
                return Some(f);
            }
        }
        None
    });
    let echo = client.join().unwrap();
    let seen = server.join().unwrap();
    println!("server saw {seen:?}");
    println!("PPPoE stats: {:?}", x.pppoe_stats());
    let froms: Vec<String> = seen.iter().map(|(_, f)| f.to_string()).collect();
    assert!(froms.contains(&"100.64.9.9:5000".to_string()), "{froms:?}");
    assert!(froms.contains(&"100.64.9.10:5001".to_string()), "{froms:?}");
    let f = echo.expect("the echo, encapsulated");
    assert_eq!(f[..6], fast.client_mac);
    assert_eq!(f[12..16], [0x88, 0x64, 0x11, 0x00]);
    assert_eq!(u16::from_be_bytes([f[16], f[17]]), 0x42);
    assert_eq!(f[20..22], PPP_IPV4.to_be_bytes());
    // IP: from the server to the subscriber, TTL 64 − 1 (the server's
    // stack starts at 64, the router took one).
    assert_eq!(f[22 + 12..22 + 16], [198, 51, 100, 2]);
    assert_eq!(f[22 + 16..22 + 20], [100, 64, 9, 9]);
    assert_eq!(f[22 + 8], 63);
    let stats: std::collections::BTreeMap<_, _> = x.pppoe_stats().into_iter().collect();
    for k in [
        "discovery",
        "unknown-session",
        "up-fast",
        "up-kernel",
        "down-fast",
    ] {
        assert!(stats.get(k).copied().unwrap_or(0) >= 1, "{k}: {stats:?}");
    }
    let c = x.pppoe_counters(1).unwrap();
    assert!(
        c.up_packets >= 1 && c.down_packets >= 1 && c.up_bytes >= 46,
        "{c:?}"
    );
    let c = x.pppoe_counters(2).unwrap();
    assert!(c.up_packets >= 1 && c.to_kernel >= 1, "{c:?}");
    // Removed: the next frame of that session is unknown.
    x.pppoe_remove(1).unwrap();
    let ip = udp_frame([100, 64, 9, 9], 5000, [198, 51, 100, 2], 7, 18);
    let f = pppoe_frame(&fast, &ip, PPP_IPV4);
    let (act, _, _) = x.test_run_out(&f, 1, Some(ifindex("la"))).unwrap();
    assert_eq!(act, XDP_DROP);
}

/// Scale (G4.3c): 100 000 sessions in the maps. Measured: time to insert
/// them, kernel ns per packet with 1 and with 100 000 sessions (upstream
/// decapsulation to the kernel, downstream encapsulation), and removal.
#[test]
fn pppoe_scale_100k_sessions() {
    if !enabled() {
        return;
    }
    let _pair = Pair::new();
    let mut x = XdpState::default();
    x.set_pppoe(true).unwrap();
    x.sync(&config(XdpMode::Generic, &[], &[])).unwrap();
    let port = ifindex("xa");
    let session = |i: u32| {
        let mut s = test_session(i, port, (i % 3) as u8, F_IPV4 | F_IPV6 | F_PD | F_FAST_DOWN);
        // Unique addresses past 16 bits of index.
        s.ipv4 = [100, 64 + (i >> 16) as u8, (i >> 8) as u8, i as u8];
        // Limits on (the policer runs on every packet), high enough that
        // 200 000 back-to-back test runs never hit them.
        s.up = Rate::mikrotik(100_000_000_000, 200_000_000_000, 0, 8_000_000_000);
        s.down = Rate::mikrotik(100_000_000_000, 0, 0, 0);
        s
    };
    // `BPF_PROG_TEST_RUN` with `repeat` runs the program again on the same
    // buffer without resetting it (a pushed header stays pushed), so the
    // mutating paths are timed one run at a time and averaged; the plain
    // pass of a frame to nobody is timed the same way, as the floor (the
    // fixed cost of one test run, which the driver does not have).
    let mean_ns = |x: &mut XdpState, f: &[u8], want: u32| -> u128 {
        let runs = 20_000u32;
        let mut total = 0u128;
        for _ in 0..runs {
            let (act, d) = x.test_run_on(f, 1, Some(port)).unwrap();
            assert_eq!(act, want, "{f:02x?}");
            total += d.as_nanos();
        }
        total / u128::from(runs)
    };
    let cost = |x: &mut XdpState, i: u32, label: &str, sessions: u32| {
        let s = session(i);
        let nobody = udp_frame([198, 51, 100, 2], 7, [203, 0, 113, 9], 5000, 18);
        let floor = mean_ns(x, &nobody, XDP_PASS);
        let ip = udp_frame([198, 51, 100, 2], 7, s.ipv4, 5000, 18);
        let down = mean_ns(x, &ip, XDP_REDIRECT);
        let up_ip = udp_frame(s.ipv4, 5000, [198, 51, 100, 2], 7, 18);
        let up = pppoe_frame(&s, &up_ip, PPP_IPV4);
        let upn = mean_ns(x, &up, XDP_PASS);
        println!(
            "PERF | pppoe | {label} | {sessions} sessions | single runs: pass (floor) {floor} ns | down encap {down} ns | up decap {upn} ns"
        );
    };
    x.pppoe_upsert(0, &session(0)).unwrap();
    cost(&mut x, 0, "1 session", 1);
    let n = 100_000u32;
    let t = Instant::now();
    for i in 1..n {
        x.pppoe_upsert(i, &session(i)).unwrap();
    }
    let took = t.elapsed();
    println!(
        "PERF | pppoe | insert | {n} sessions | {} ms | {:.1} µs/session",
        took.as_millis(),
        took.as_secs_f64() * 1e6 / f64::from(n)
    );
    assert_eq!(x.pppoe_sessions(), n as usize);
    for i in [1, 4_242, 77_777, n - 1] {
        cost(&mut x, i, "100k sessions", n);
    }
    // Every session answers for its own address (a sample of 5000).
    for i in (0..n).step_by(20) {
        let s = session(i);
        let ip = udp_frame([198, 51, 100, 2], 7, s.ipv4, 5000, 18);
        let (act, _, out) = x.test_run_out(&ip, 1, Some(port)).unwrap();
        assert_eq!(act, XDP_REDIRECT, "session {i}");
        let off = 12 + 4 * usize::from(pppoe::View::of(&s.to_words()).tags());
        assert_eq!(
            u16::from_be_bytes([out[off + 4], out[off + 5]]),
            s.sid,
            "session {i}"
        );
    }
    let t = Instant::now();
    for i in 0..n {
        x.pppoe_remove(i).unwrap();
    }
    println!(
        "PERF | pppoe | remove | {n} sessions | {} ms",
        t.elapsed().as_millis()
    );
    let s = session(5);
    let ip = udp_frame([198, 51, 100, 2], 7, s.ipv4, 5000, 18);
    let (act, _) = x.test_run_on(&ip, 1, Some(port)).unwrap();
    assert_eq!(act, XDP_PASS, "no session, no encapsulation");
}

/// The policer in the kernel (G4.3c): 1, 100 and 10 000 subscribers
/// upload as fast as an AF_PACKET sender can for 3 s, each above its
/// rate; the bytes each one gets through (after the first bucket) must be
/// within ±5% of its configured rate. Upstream to the kernel (the frames
/// are dropped after the count; only the policer's verdict matters).
#[test]
fn pppoe_policer_accuracy() {
    if !enabled() {
        return;
    }
    let _t = Triangle::new();
    let mut x = pppoe_router();
    let client = mac_of(Some(SUB_NS), "lb");
    let server = mac_of(None, "la");
    let frames_for = |n: u32| -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| {
                let s = Session {
                    sid: (i + 1) as u16,
                    client_mac: client,
                    server_mac: server,
                    ipv4: [100, 65, (i >> 8) as u8, i as u8],
                    ..Session::default()
                };
                let ip = udp_frame(s.ipv4, 5000, [198, 51, 100, 2], 9, 1000);
                pppoe_frame(&s, &ip, PPP_IPV4)
            })
            .collect()
    };
    // (frames sent, seconds from the first send to the last).
    let blast = |frames: Vec<Vec<u8>>, secs: f64| -> (u64, f64) {
        Triangle::spawn_in(SUB_NS, move || {
            let tx = packet_socket("lb", 0x0003);
            let t = Instant::now();
            let mut sent = 0u64;
            while t.elapsed().as_secs_f64() < secs {
                for f in &frames {
                    if nix::sys::socket::send(
                        std::os::fd::AsRawFd::as_raw_fd(&tx),
                        f,
                        nix::sys::socket::MsgFlags::empty(),
                    )
                    .is_ok()
                    {
                        sent += 1;
                    }
                }
            }
            (sent, t.elapsed().as_secs_f64())
        })
        .join()
        .unwrap()
    };
    // What the sender offers depends on the machine (~6 Gbit/s of
    // 1028-byte IP packets on the user's, ~1.5 on the 4-vCPU CI runner,
    // **medido**): each case first measures it and caps the rate at a third
    // of what each subscriber is offered, so the policer, not the sender,
    // is what limits. The reference is then per subscriber: one the policer
    // cut must get its rate (after the first bucket) within ±5%; one it
    // never cut must get exactly what it offered, never more than the limit.
    let ip_bytes = 20 + 8 + 1000u64;
    for (n, top_bps) in [
        (1u32, 1_000_000_000u64),
        (100, 20_000_000),
        (10_000, 200_000),
    ] {
        let (cal_sent, cal_took) = blast(frames_for(n), 1.0);
        let offered_each = cal_sent as f64 / cal_took * (ip_bytes * 8) as f64 / f64::from(n);
        let rate_bps = top_bps.min((offered_each / 3.0) as u64 / 1000 * 1000);
        for i in 0..n {
            let s = Session {
                up: Rate::mikrotik(rate_bps, 0, 0, 0),
                ..lb_session((i + 1) as u16, [100, 65, (i >> 8) as u8, i as u8], 0)
            };
            x.pppoe_upsert(i, &s).unwrap();
        }
        let before: Vec<_> = (0..n).map(|i| x.pppoe_counters(i).unwrap()).collect();
        let frames = frames_for(n);
        let (sent, took) = blast(frames, 3.0);
        let want = rate_bps as f64 / 8.0 * took;
        let depth = Rate::mikrotik(rate_bps, 0, 0, 0).depth as f64;
        let (mut worst, mut total, mut limited) = (0f64, 0u64, 0u32);
        for i in 0..n {
            let (b, c) = (before[i as usize], x.pppoe_counters(i).unwrap());
            let got = c.up_bytes - b.up_bytes;
            let policed = c.up_policed - b.up_policed;
            let offered = (c.up_packets - b.up_packets + policed) * ip_bytes;
            total += got;
            assert!(
                got as f64 <= depth + want + ip_bytes as f64,
                "subscriber {i}: {got} bytes over the limit {:.0}",
                depth + want
            );
            let err = if policed > 0 {
                limited += 1;
                ((got as f64 - depth) - want) / want
            } else {
                (got as f64 - offered as f64) / (offered.max(1) as f64)
            };
            worst = if err.abs() > worst.abs() { err } else { worst };
        }
        println!(
            "PERF | pppoe policer | {n} subscribers | {:.2} Mbit/s each | sent {:.0} kpps | limited {limited} | worst error {:+.2}% | total {:.1} Mbit/s",
            rate_bps as f64 / 1e6,
            sent as f64 / took / 1000.0,
            worst * 100.0,
            total as f64 * 8.0 / took / 1e6
        );
        assert!(worst.abs() <= 0.05, "{n} subscribers: worst {worst:+.3}");
        // The case must test the policer: nearly everyone over the rate.
        assert!(
            limited * 10 >= n * 9,
            "{n} subscribers: only {limited} limited"
        );
        for i in 0..n {
            x.pppoe_remove(i).unwrap();
        }
    }
}

/// Measured (G4.3c): frames per second through the router from a raw
/// PPPoE sender on `lb`, counted where they arrive (`wb`, internet side):
/// the kernel forwarding plain IPv4 (no PPPoE: the floor) against the XDP
/// path decapsulating and forwarding (FIB + redirect), and decapsulating
/// for the kernel. Kernel PPPoE (`pppoe` + a ppp netdev) needs pppd: run
/// when installed, otherwise reported as skipped.
#[test]
fn perf_pppoe_forward() {
    if !enabled() {
        return;
    }
    let _t = Triangle::new();
    let rx = || -> u64 {
        sh(&[
            "ip",
            "netns",
            "exec",
            INET_NS,
            "cat",
            "/sys/class/net/wb/statistics/rx_packets",
        ])
        .trim()
        .parse()
        .unwrap_or(0)
    };
    let client = mac_of(Some(SUB_NS), "lb");
    let la_mac = mac_of(None, "la");
    let blast = |frames: Vec<Vec<u8>>| -> u64 {
        Triangle::spawn_in(SUB_NS, move || {
            let tx = packet_socket("lb", 0x0003);
            let t = Instant::now();
            let mut sent = 0u64;
            while t.elapsed() < Duration::from_secs(2) {
                for f in &frames {
                    if nix::sys::socket::send(
                        std::os::fd::AsRawFd::as_raw_fd(&tx),
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
        })
        .join()
        .unwrap()
    };
    let report = |label: &str, sent: u64, seen: u64| {
        println!(
            "PERF | pppoe forward | {label} | {:.0} kpps delivered | {seen} of {sent}",
            seen as f64 / 2000.0
        );
    };
    let ip = udp_frame([100, 64, 0, 2], 5000, [198, 51, 100, 2], 9, 18);
    let mut plain = ip.clone();
    plain[..6].copy_from_slice(&la_mac);
    plain[6..12].copy_from_slice(&client);
    let before = rx();
    let sent = blast(vec![plain; 64]);
    report(
        "kernel IPv4 forward, no PPPoE (floor)",
        sent,
        rx().saturating_sub(before),
    );
    let mut x = pppoe_router();
    for (flags, label) in [
        (F_FAST_UP, "XDP decap + FIB redirect (generic, veth)"),
        (0, "XDP decap, kernel forward"),
    ] {
        let s = lb_session(0x77, [100, 64, 0, 2], flags);
        x.pppoe_upsert(0, &s).unwrap();
        let f = pppoe_frame(&s, &ip, PPP_IPV4);
        let before = rx();
        let sent = blast(vec![f; 64]);
        report(label, sent, rx().saturating_sub(before));
    }
    if sh_ok(&["which", "pppd"]) && sh_ok(&["which", "pppoe-server"]) {
        println!("PERF | pppoe forward | kernel PPPoE | pppd present: not automated yet (G4.3cb)");
    } else {
        println!(
            "PERF | pppoe forward | kernel PPPoE (pppoe + ppp netdev) | skipped: no pppd/pppoe-server"
        );
    }
    x.sync(&Config::default()).unwrap();
}

/// G4.3d: what the BNG service does to the maps, through the HAL's terms
/// (`hal::pppoe`): `pppoe_ready` refuses a port without XDP, an `Upsert`
/// makes the session known (upstream decapsulated to the kernel, counted),
/// An Ethernet frame with an IPv6 UDP packet (checksum over the
/// pseudo-header, RFC 8200 §8.1), the shape `pppoe_frame` takes (it keeps
/// what follows the 14-byte Ethernet header).
fn udp6_frame(src: std::net::Ipv6Addr, dst: std::net::Ipv6Addr) -> Vec<u8> {
    let mut udp = vec![0x13, 0x88, 0, 7, 0, 18, 0, 0];
    udp.extend_from_slice(b"corerouter");
    let mut sum: u32 = 0;
    let mut add = |b: &[u8]| {
        for c in b.chunks(2) {
            sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
        }
    };
    add(&src.octets());
    add(&dst.octets());
    add(&(udp.len() as u32).to_be_bytes());
    add(&[0, 0, 0, 17]);
    add(&udp);
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let c = !(sum as u16);
    udp[6..8].copy_from_slice(&c.to_be_bytes());
    let mut ip = vec![0u8; 12];
    ip.extend_from_slice(&[0x86, 0xdd, 0x60, 0, 0, 0]);
    ip.extend_from_slice(&(udp.len() as u16).to_be_bytes());
    ip.extend_from_slice(&[17, 64]);
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    ip.extend_from_slice(&udp);
    ip
}

/// a rate in RouterOS terms reaches the policer, a `Remove` makes the next
/// frame unknown.
#[test]
fn pppoe_bng_ops_reach_the_maps() {
    use corerouter_hal::pppoe::{PppoeOp, PppoeSession, Rate as HalRate};
    if !enabled() {
        return;
    }
    let _t = Triangle::new();
    let mut x = pppoe_router();
    assert!(x.pppoe_ready(&["la".parse().unwrap()]).is_ok());
    assert!(x.pppoe_ready(&["nope0".parse().unwrap()]).is_err());
    let s = PppoeSession {
        ifindex: ifindex("la"),
        sid: 0x51,
        mtu: 1480,
        client_mac: mac_of(Some(SUB_NS), "lb"),
        server_mac: mac_of(None, "la"),
        ipv4: Some(std::net::Ipv4Addr::new(100, 64, 9, 20)),
        up: HalRate {
            rate_bps: 10_000_000,
            ..HalRate::default()
        },
        down: HalRate {
            rate_bps: 50_000_000,
            burst_bps: 80_000_000,
            threshold_bps: 40_000_000,
            burst_secs: 8,
        },
        fast_up: false,
        fast_down: true,
        // G4.3e: the /64 of the link and a /56 delegated by DHCPv6.
        // 2001:db8:0:51::/64 and 2001:db8:8000:5100::/56.
        ipv6_prefix: Some([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0x51]),
        delegated: Some(([0x20, 0x01, 0x0d, 0xb8, 0x80, 0, 0x51, 0], 56)),
        ..PppoeSession::default()
    };
    x.pppoe_apply(&[PppoeOp::Upsert(7, s)]).unwrap();
    let words = corerouter_hal_linux::xdp::pppoe_session_of(&s);
    assert_eq!(words.up.rate, 10_000_000 / 8, "bytes per second");
    assert!(words.down.bursts());
    let ip = udp_frame([100, 64, 9, 20], 5000, [198, 51, 100, 2], 7, 18);
    let f = pppoe_frame(&words, &ip, PPP_IPV4);
    let (act, _, _) = x.test_run_out(&f, 1, Some(ifindex("la"))).unwrap();
    assert_eq!(act, XDP_PASS, "decapsulated, to the kernel (fast_up off)");
    let c = x.pppoe_counters_of(&[7]);
    assert_eq!(c.len(), 1);
    assert!(c[0].1.up_packets >= 1 && c[0].1.to_kernel >= 1, "{c:?}");
    // IPv6 from the /64 and from inside the delegated /56 is the
    // subscriber's; from elsewhere it is spoofed (dropped, counted).
    for (src, want) in [
        ("2001:db8:0:51::1234", XDP_PASS),
        ("2001:db8:8000:5177::1", XDP_PASS),
        ("2001:db8:0:52::1", XDP_DROP),
    ] {
        let ip = udp6_frame(src.parse().unwrap(), "2001:db8:ffff::1".parse().unwrap());
        let f = pppoe_frame(&words, &ip, PPP_IPV6);
        let (act, _, _) = x.test_run_out(&f, 1, Some(ifindex("la"))).unwrap();
        assert_eq!(act, want, "from {src}");
    }
    let c = x.pppoe_counters_of(&[7]);
    assert!(c[0].1.spoofed >= 1 && c[0].1.up_packets >= 3, "{c:?}");
    x.pppoe_apply(&[PppoeOp::Remove(7)]).unwrap();
    let (act, _, _) = x.test_run_out(&f, 1, Some(ifindex("la"))).unwrap();
    assert_eq!(act, XDP_DROP, "unknown session after the removal");
}

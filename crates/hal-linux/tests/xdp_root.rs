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
//!    and pktgen over veth with no filter, nftables raw drop and XDP drop.
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
use corerouter_hal_linux::xdp::XdpState;
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

/// Measured (4): pktgen blasting 64-byte UDP over veth into `xa` from
/// random sources; how many packets per second the receive side gets
/// through with no filter, with an nftables raw-table drop of the sources
/// (the kernel path the Firewall uses), and with XDP generic and native
/// drop. One core does both sides (veth), so this compares costs; it is
/// not a NIC's line rate.
#[test]
fn perf_pktgen_veth() {
    if !enabled() {
        return;
    }
    if !std::path::Path::new("/proc/net/pktgen").exists() && !sh_ok(&["modprobe", "pktgen"]) {
        println!("PERF | pktgen unavailable: skipped");
        return;
    }
    let pair = Pair::new();
    let _ = &pair;
    let mac = sh(&["cat", "/sys/class/net/xa/address"]).trim().to_owned();
    let count: u64 = 1_000_000;
    let run = |label: &str, counter: &dyn Fn() -> u64| {
        let before = counter();
        let t = Instant::now();
        pktgen(&mac, count);
        let secs = t.elapsed().as_secs_f64();
        let seen = counter().saturating_sub(before);
        println!(
            "PERF | pktgen veth | {label} | {:.0} kpps handled | {seen} of {count} in {secs:.2} s",
            seen as f64 / secs / 1000.0
        );
    };
    let rx = || {
        sh(&["cat", "/sys/class/net/xa/statistics/rx_packets"])
            .trim()
            .parse()
            .unwrap_or(0)
    };
    run("no filter (kernel stack)", &rx);
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
        let nft_count = || {
            let out = sh(&["nft", "list chain inet crxdp raw"]);
            out.split("packets ")
                .nth(1)
                .and_then(|t| t.split_whitespace().next())
                .and_then(|n| n.parse().ok())
                .unwrap_or(0)
        };
        run("nftables raw drop", &nft_count);
        sh(&["nft", "delete table inet crxdp"]);
    }
    for mode in [XdpMode::Generic, XdpMode::Native] {
        let mut x = XdpState::default();
        x.sync(&config(mode, &["198.18.0.0/15"], &[])).unwrap();
        let blocked = |x: &mut XdpState| port(&x.status(0)).counters[1].0;
        let before = blocked(&mut x);
        let t = Instant::now();
        pktgen(&mac, count);
        let secs = t.elapsed().as_secs_f64();
        let seen = blocked(&mut x).saturating_sub(before);
        println!(
            "PERF | pktgen veth | XDP {} drop | {:.0} kpps handled | {seen} of {count} in {secs:.2} s",
            mode.name(),
            seen as f64 / secs / 1000.0
        );
        x.sync(&Config::default()).unwrap();
    }
}

/// Send `count` UDP packets from 198.18.0.0/15 to `xa` (MAC `mac`) out of
/// `xb`, with the kernel's packet generator, in the peer namespace.
fn pktgen(mac: &str, count: u64) {
    let script = format!(
        "set -e
pg() {{ echo \"$2\" > /proc/net/pktgen/$1; }}
pg kpktgend_0 rem_device_all
pg kpktgend_0 'add_device xb'
pg xb 'count {count}'
pg xb 'pkt_size 64'
pg xb 'delay 0'
pg xb 'dst 10.99.0.1'
pg xb 'dst_mac {mac}'
pg xb 'src_min 198.18.0.1'
pg xb 'src_max 198.19.255.254'
pg xb 'flag IPSRC_RND'
pg xb 'udp_dst_min 9'
pg xb 'udp_dst_max 9'
echo start > /proc/net/pktgen/pgctrl
# Let go of xb before anyone deletes it: a device pktgen still holds never
# finishes unregistering, with the rtnl lock held (the CI VM hung on it).
echo reset > /proc/net/pktgen/pgctrl
"
    );
    // pktgen blocks until done; a stuck generator must not hold the test.
    let ok = sh_ok(&[
        "timeout", "60", "ip", "netns", "exec", PEER_NS, "sh", "-c", &script,
    ]);
    if !ok {
        println!("PERF | pktgen did not finish in 60 s");
    }
}

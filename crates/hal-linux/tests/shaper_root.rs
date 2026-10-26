//! G4.9b / G4.3cc: the queues' tc programs loaded for real. Root only
//! (`COREROUTER_XDP_ROOT=1`, run by `cargo xtask xdp-root` or the VM lab in
//! a throwaway namespace, like `xdp_root.rs`); elsewhere every test returns
//! at once.
//!
//! The test process is the router. Two peer namespaces:
//!
//! ```text
//!  crss (server, 10.68.0.2) ─ ss1 ═ ss0 ─ router ─ sc0 ═ sc1 ─ crsc (clients)
//!                                       10.68.0.1   10.69.0.1   10.69.0.2
//! ```
//!
//! `crsc` answers for all of 10.70.0.0/16 (a local route: every address a
//! target), and the router reaches it through 10.69.0.2 (one neighbor, not
//! 65 536). Targets are shaped on `sc0`'s egress (download) and policed on
//! `ss0`'s ingress (upload of the server, the policer's case).
//!
//! Measured (`PERF |` lines): accuracy at 1, 100 and 10 000 targets; TCP
//! goodput through the shaper against the policer at the same rate (20 ms
//! RTT); EDT against HTB (one root, and per-CPU HTB behind RPS/XPS
//! steering, the kernel's form of LibreQoS's cpumap) at 1 000 and 10 000
//! targets; the policer under 1/4/8/16 CPUs on one subscriber.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![cfg(target_os = "linux")]

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use corerouter_hal::queue::{DirSpec, Kind, QueueSpec, ShaperPlan};
use corerouter_hal_linux::xdp::XdpState;
use corerouter_model::IfName;
use ipnet::IpNet;

const SERVER_NS: &str = "crss";
const CLIENT_NS: &str = "crsc";

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

fn ns(ns: &str, args: &[&str]) -> String {
    let mut v = vec!["ip", "netns", "exec", ns];
    v.extend_from_slice(args);
    sh(&v)
}

/// The two peer namespaces and their veth pairs (removed on drop).
struct Lab;

impl Lab {
    /// `queues`: transmit queues of the router's `sc0` (the per-CPU HTB
    /// case wants several).
    fn new(queues: u16) -> Self {
        Lab::down();
        let q = queues.to_string();
        for n in [SERVER_NS, CLIENT_NS] {
            sh(&["ip", "netns", "add", n]);
        }
        sh(&[
            "ip",
            "link",
            "add",
            "sc0",
            "numtxqueues",
            &q,
            "numrxqueues",
            &q,
            "type",
            "veth",
            "peer",
            "name",
            "sc1",
            "numtxqueues",
            &q,
            "numrxqueues",
            &q,
        ]);
        sh(&[
            "ip",
            "link",
            "add",
            "ss0",
            "numtxqueues",
            &q,
            "numrxqueues",
            &q,
            "type",
            "veth",
            "peer",
            "name",
            "ss1",
            "numtxqueues",
            &q,
            "numrxqueues",
            &q,
        ]);
        sh(&["ip", "link", "set", "sc1", "netns", CLIENT_NS]);
        sh(&["ip", "link", "set", "ss1", "netns", SERVER_NS]);
        sh(&["ip", "addr", "add", "10.69.0.1/30", "dev", "sc0"]);
        sh(&["ip", "addr", "add", "10.68.0.1/30", "dev", "ss0"]);
        for l in ["sc0", "ss0", "lo"] {
            sh(&["ip", "link", "set", l, "up"]);
        }
        sh(&["ip", "route", "replace", "10.70.0.0/16", "via", "10.69.0.2"]);
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
        ns(
            CLIENT_NS,
            &["ip", "addr", "add", "10.69.0.2/30", "dev", "sc1"],
        );
        ns(CLIENT_NS, &["ip", "link", "set", "sc1", "up"]);
        ns(CLIENT_NS, &["ip", "link", "set", "lo", "up"]);
        // Every address of 10.70.0.0/16 is this namespace's.
        ns(
            CLIENT_NS,
            &["ip", "route", "add", "local", "10.70.0.0/16", "dev", "lo"],
        );
        ns(
            CLIENT_NS,
            &["ip", "route", "add", "default", "via", "10.69.0.1"],
        );
        ns(
            SERVER_NS,
            &["ip", "addr", "add", "10.68.0.2/30", "dev", "ss1"],
        );
        ns(SERVER_NS, &["ip", "link", "set", "ss1", "up"]);
        ns(SERVER_NS, &["ip", "link", "set", "lo", "up"]);
        ns(
            SERVER_NS,
            &["ip", "route", "add", "default", "via", "10.68.0.1"],
        );
        ns(SERVER_NS, &["ping", "-c", "1", "-W", "2", "10.70.0.1"]);
        Lab
    }

    fn down() {
        for l in ["sc0", "ss0"] {
            let _ = sh_ok(&["ip", "link", "del", l]);
        }
        for n in [SERVER_NS, CLIENT_NS] {
            let _ = sh_ok(&["ip", "netns", "del", n]);
        }
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

impl Drop for Lab {
    fn drop(&mut self) {
        Lab::down();
    }
}

fn name(s: &str) -> IfName {
    s.parse().unwrap()
}

/// Target `i`: 10.70.x.y with y in 1..=254 (no network nor broadcast
/// look-alikes).
fn target(i: u32) -> Ipv4Addr {
    Ipv4Addr::new(10, 70, (i / 254) as u8, (i % 254) as u8 + 1)
}

fn fifo(rate_bps: u64, ms: u64) -> Kind {
    Kind::Fifo {
        limit_bytes: (rate_bps / 8 * ms / 1000).max(3028),
    }
}

/// `n` download queues of `rate_bps` on the targets, shaped on `sc0`.
fn download_plan(n: u32, rate_bps: u64, kind: Kind) -> ShaperPlan {
    let mut p = ShaperPlan {
        ports: vec![name("sc0")],
        ..ShaperPlan::default()
    };
    for i in 0..n {
        p.queues.push(QueueSpec {
            key: format!("q{i}"),
            upload: DirSpec::default(),
            download: DirSpec {
                rate_bps,
                bucket_milli: 100,
                kind,
                ..DirSpec::default()
            },
        });
        p.prefixes
            .push((IpNet::from(std::net::IpAddr::V4(target(i))), i));
    }
    p
}

/// Count IP bytes per destination arriving on `sc1` until `stop`, then
/// `drain` more.
fn receiver(
    stop: Arc<AtomicBool>,
    drain: Duration,
) -> std::thread::JoinHandle<HashMap<Ipv4Addr, u64>> {
    Lab::spawn_in(CLIENT_NS, move || {
        let sock = socket2::Socket::new(
            socket2::Domain::PACKET,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::from(i32::from(0x0800u16.to_be()))),
        )
        .unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        // Root: past `rmem_max` (a drop here would read as a shaper error).
        let _ = nix::sys::socket::setsockopt(
            &sock,
            nix::sys::socket::sockopt::RcvBufForce,
            &(256 << 20),
        );
        let mut got: HashMap<Ipv4Addr, u64> = HashMap::new();
        let mut buf = [0u8; 2048];
        let mut stopped: Option<Instant> = None;
        loop {
            if stopped.is_none() && stop.load(Ordering::Relaxed) {
                stopped = Some(Instant::now());
            }
            if stopped.is_some_and(|t| t.elapsed() > drain) {
                break;
            }
            let Ok(n) = std::io::Read::read(&mut &sock, &mut buf) else {
                continue;
            };
            if n < 20 {
                continue;
            }
            let b = &buf[..n];
            let dst = Ipv4Addr::new(b[16], b[17], b[18], b[19]);
            let len = u64::from(u16::from_be_bytes([b[2], b[3]]));
            *got.entry(dst).or_insert(0) += len;
        }
        got
    })
}

/// Send UDP of `payload` bytes round-robin to targets `0..n` from the server
/// for `secs` (`threads` senders): (packets sent, seconds).
fn blast(n: u32, payload: usize, secs: f64, threads: u32) -> (u64, f64) {
    blast_paced(n, payload, secs, threads, 0)
}

/// [`blast`] at `pps` packets per second in all (0: as fast as it goes).
fn blast_paced(n: u32, payload: usize, secs: f64, threads: u32, pps: u64) -> (u64, f64) {
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            Lab::spawn_in(SERVER_NS, move || {
                let s = UdpSocket::bind(("10.68.0.2", 20_000 + t as u16)).unwrap();
                let data = vec![0u8; payload];
                let start = Instant::now();
                let mut sent = 0u64;
                let mut i = t;
                let each = pps as f64 / f64::from(threads);
                while start.elapsed().as_secs_f64() < secs {
                    if each > 0.0 {
                        let due = sent as f64 / each;
                        let now = start.elapsed().as_secs_f64();
                        if due > now {
                            std::thread::sleep(Duration::from_secs_f64(due - now));
                        }
                    }
                    for _ in 0..64 {
                        let to = SocketAddrV4::new(target(i % n), 9);
                        if s.send_to(&data, to).is_ok() {
                            sent += 1;
                        }
                        i = i.wrapping_add(threads);
                    }
                }
                (sent, start.elapsed().as_secs_f64())
            })
        })
        .collect();
    let mut sent = 0;
    let mut took: f64 = 0.0;
    for h in handles {
        let (s, t) = h.join().unwrap();
        sent += s;
        took = took.max(t);
    }
    (sent, took)
}

/// The verifier takes the three tc programs; they attach to a port, `fq`
/// goes on it, and taking the plan away restores the port's qdisc.
#[test]
fn shaper_programs_load_and_attach() {
    if !enabled() {
        return;
    }
    let _lab = Lab::new(1);
    let mut x = XdpState::default();
    let plan = download_plan(10, 10_000_000, Kind::default());
    x.shaper_apply(&plan).unwrap();
    let st = x.shaper_status();
    assert!(st.unavailable.is_none(), "{:?}", st.unavailable);
    assert_eq!(
        st.ports.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        ["sc0"]
    );
    assert_eq!(st.queues.len(), 10);
    let q = sh(&["tc", "qdisc", "show", "dev", "sc0"]);
    assert!(q.contains("qdisc fq"), "{q}");
    // Traffic to a target is shaped (counted by its queue).
    ns(
        SERVER_NS,
        &["ping", "-c", "3", "-i", "0.2", "-W", "2", "10.70.0.1"],
    );
    let st = x.shaper_status();
    // 10.70.0.1 is target 0.
    let (_, c) = st.queues.iter().find(|(k, _)| k == "q0").unwrap();
    assert!(c.packets[1] >= 3, "{c:?} {:?}", st.stats);
    x.shaper_apply(&ShaperPlan::default()).unwrap();
    let q = sh(&["tc", "qdisc", "show", "dev", "sc0"]);
    assert!(!q.contains("qdisc fq "), "{q}");
}

/// ±5% at 1, 100 and 10 000 targets (the G4.3ca criterion). The router's
/// work runs in the sender's softirq (veth), so what the sender offers
/// depends on the shaping itself: each case runs, reads the offered load
/// from the queues' counters (packets + drops) and runs again at a third of
/// it until every target is offered at least twice its rate.
#[test]
fn shaper_accuracy() {
    if !enabled() {
        return;
    }
    let _lab = Lab::new(1);
    let mut x = XdpState::default();
    for (n, top_bps) in [
        (1u32, 1_000_000_000u64),
        (100, 20_000_000),
        (10_000, 200_000),
    ] {
        // 10 000 targets share what the VM forwards (~300 Mbit/s in a debug
        // build): small packets keep each target at hundreds of packets.
        let payload = if n >= 10_000 { 100usize } else { 1000 };
        let ip_bytes = (payload + 28) as u64;
        let mut rate = top_bps;
        // Enough packets per target that one is under 1% of its total.
        let secs = if n >= 10_000 { 12.0 } else { 3.0 };
        for round in 0..4 {
            x.shaper_apply(&ShaperPlan::default()).unwrap();
            x.shaper_apply(&download_plan(n, rate, fifo(rate, 20)))
                .unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            // Counting stops with the sender (20 ms for the socket's own
            // buffer): what the queues still hold then is not the rate.
            let rx = receiver(stop.clone(), Duration::from_millis(20));
            std::thread::sleep(Duration::from_millis(50));
            let (sent, took) = blast(n, payload, secs, 2);
            stop.store(true, Ordering::Relaxed);
            let got = rx.join().unwrap();
            let st = x.shaper_status();
            let counters: HashMap<String, corerouter_hal::queue::QueueCounters> =
                st.queues.iter().cloned().collect();
            let offered_min = (0..n)
                .map(|i| {
                    let c = counters[&format!("q{i}")];
                    (c.packets[1] + c.dropped[1]) * ip_bytes * 8
                })
                .min()
                .unwrap_or(0) as f64
                / took;
            if offered_min < 2.0 * rate as f64 && round < 3 {
                rate = ((offered_min / 3.0) as u64 / 1000 * 1000).max(8_000);
                continue;
            }
            let want = rate as f64 / 8.0 * took;
            // The first bucket: 0.1 s of the rate, at least two frames.
            let depth = corerouter_dataplane_ebpf_common::policer::default_depth(rate / 8) as f64;
            let (mut worst, mut total) = (0f64, 0u64);
            for i in 0..n {
                let b = got.get(&target(i)).copied().unwrap_or(0);
                total += b;
                let err = (b as f64 - depth - want) / want;
                worst = if err.abs() > worst.abs() { err } else { worst };
            }
            println!(
                "PERF | shaper accuracy | {n} targets | {:.3} Mbit/s each | offered >= {:.1}x | sent {:.0} kpps | worst error {:+.2}% | total {:.1} Mbit/s | {:?}",
                rate as f64 / 1e6,
                offered_min / rate as f64,
                sent as f64 / took / 1000.0,
                worst * 100.0,
                total as f64 * 8.0 / took / 1e6,
                st.stats
            );
            assert!(
                offered_min >= 2.0 * rate as f64,
                "{n} targets: not offered enough"
            );
            assert!(worst.abs() <= 0.05, "{n} targets: worst {worst:+.3}");
            break;
        }
    }
}

/// One iperf3 run (TCP, server → client, `secs`) with a ping alongside:
/// (goodput Mbit/s, retransmits, mean ping ms under load).
fn iperf(secs: u32) -> (f64, u64, f64) {
    let _ = sh_ok(&["pkill", "-f", "iperf3 -s -1 -B 10.70.0.5"]);
    let mut server = Command::new("ip")
        .args([
            "netns",
            "exec",
            CLIENT_NS,
            "iperf3",
            "-s",
            "-1",
            "-B",
            "10.70.0.5",
        ])
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let pinger = std::thread::spawn(move || {
        let count = (secs * 10).saturating_sub(10).to_string();
        let out = Command::new("ip")
            .args([
                "netns",
                "exec",
                SERVER_NS,
                "ping",
                "-n",
                "-q",
                "-i",
                "0.1",
                "-c",
                &count,
                "10.70.0.6",
            ])
            .output()
            .unwrap();
        // "rtt min/avg/max/mdev = 20.1/35.2/…"
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .find_map(|l| l.split('=').nth(1).map(str::to_owned))
            .and_then(|v| {
                v.trim()
                    .split('/')
                    .nth(1)
                    .and_then(|a| a.parse::<f64>().ok())
            })
            .unwrap_or(f64::NAN)
    });
    let out = Command::new("ip")
        .args([
            "netns",
            "exec",
            SERVER_NS,
            "iperf3",
            "-c",
            "10.70.0.5",
            "-t",
            &secs.to_string(),
            "-J",
        ])
        .output()
        .unwrap();
    let _ = server.wait();
    let ping = pinger.join().unwrap();
    let j: serde_json::Value =
        serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null);
    let bps = j["end"]["sum_received"]["bits_per_second"]
        .as_f64()
        .unwrap_or(0.0);
    let retr = j["end"]["sum_sent"]["retransmits"].as_u64().unwrap_or(0);
    (bps / 1e6, retr, ping)
}

/// TCP through the shaper against the policer at the same rate (50 Mbit/s,
/// 20 ms of RTT added on the server's side): goodput, retransmits and the
/// delay a ping sees meanwhile (the policer case is the G4.3c XDP
/// policer's algorithm, in `shape_ingress` on the server's port).
#[test]
fn tcp_shaper_vs_policer() {
    if !enabled() {
        return;
    }
    if !sh_ok(&["which", "iperf3"]) {
        println!("PERF | tcp shaper vs policer | skipped: no iperf3");
        return;
    }
    let _lab = Lab::new(1);
    ns(
        SERVER_NS,
        &[
            "tc", "qdisc", "add", "dev", "ss1", "root", "netem", "delay", "20ms", "limit", "100000",
        ],
    );
    if std::env::var_os("SHAPER_NO_GSO").is_some() {
        for d in ["ss0", "sc0"] {
            let _ = sh_ok(&["ethtool", "-K", d, "gso", "off", "gro", "off", "tso", "off"]);
        }
        let _ = sh_ok(&[
            "ip", "netns", "exec", SERVER_NS, "ethtool", "-K", "ss1", "gso", "off", "tso", "off",
            "gro", "off",
        ]);
        let _ = sh_ok(&[
            "ip", "netns", "exec", CLIENT_NS, "ethtool", "-K", "sc1", "gso", "off", "tso", "off",
            "gro", "off",
        ]);
    }
    let mut x = XdpState::default();
    let rate = 50_000_000u64;
    let shaped = |kind: Kind| {
        let mut p = download_plan(1, rate, kind);
        p.prefixes = vec![
            ("10.70.0.5/32".parse().unwrap(), 0),
            ("10.70.0.6/32".parse().unwrap(), 0),
        ];
        p
    };
    let policed = |bucket_milli: u32| ShaperPlan {
        queues: vec![QueueSpec {
            key: "server".into(),
            upload: DirSpec {
                rate_bps: rate,
                bucket_milli,
                kind: Kind::default(),
                ..DirSpec::default()
            },
            download: DirSpec::default(),
        }],
        prefixes: vec![("10.68.0.2/32".parse().unwrap(), 0)],
        ports: vec![name("ss0")],
        ..ShaperPlan::default()
    };
    let cases: [(&str, ShaperPlan); 5] = [
        ("none", ShaperPlan::default()),
        ("shaper fq-codel", shaped(Kind::default())),
        (
            "shaper pfifo 10 (default-small)",
            shaped(Kind::Fifo {
                limit_bytes: 10 * 1514,
            }),
        ),
        ("policer bucket 0.1 s (G4.9)", policed(100)),
        ("policer bucket 0.05 s (G4.3c)", policed(50)),
    ];
    let mut got = Vec::new();
    for (what, plan) in cases {
        x.shaper_apply(&ShaperPlan::default()).unwrap();
        x.shaper_apply(&plan).unwrap();
        let (mbps, retr, ping) = iperf(10);
        println!(
            "PERF | tcp 50 Mbit/s, 20 ms RTT | {what} | goodput {mbps:.1} Mbit/s | retransmits {retr} | ping under load {ping:.1} ms"
        );
        got.push((what, mbps, retr, ping));
    }
    x.shaper_apply(&ShaperPlan::default()).unwrap();
    let find = |w: &str| got.iter().find(|g| g.0.starts_with(w)).copied().unwrap();
    let codel = find("shaper fq-codel");
    let police = find("policer bucket 0.05");
    // The shaper holds the rate: 50 Mbit/s within 10% (TCP ramp-up).
    assert!(codel.1 >= 45.0 && codel.1 <= 52.0, "{codel:?}");
    // And never does worse than the policer at the same rate.
    assert!(codel.1 >= police.1 * 0.98, "{codel:?} vs {police:?}");
}

/// Busy CPU time (ticks of user, system, softirq) since boot.
fn cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/stat").unwrap();
    let line = stat.lines().next().unwrap();
    // cpu user nice system idle iowait irq softirq …
    let f: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|x| x.parse().ok())
        .collect();
    f[0] + f[1] + f[2] + f[5] + f[6]
}

/// Packets `dev` received in namespace `ns`.
fn rx_packets(ns_name: &str, dev: &str) -> u64 {
    ns(
        ns_name,
        &[
            "cat",
            &format!("/sys/class/net/{dev}/statistics/rx_packets"),
        ],
    )
    .trim()
    .parse()
    .unwrap_or(0)
}

/// RPS on the router's ingress (`ss0`, flows spread by hash over all CPUs)
/// and XPS on its egress (CPU c → transmit queue c mod `queues`): each
/// target's flow stays on one CPU and one queue, the kernel's form of
/// LibreQoS's cpumap steering.
fn steer(queues: u16) {
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    let all = format!("{:x}", (1u64 << cpus) - 1);
    let _ = std::fs::write("/sys/class/net/ss0/queues/rx-0/rps_cpus", &all);
    for q in 0..queues {
        let mask: u64 = (0..cpus)
            .filter(|c| c % usize::from(queues) == usize::from(q))
            .map(|c| 1u64 << c)
            .sum();
        let _ = std::fs::write(
            format!("/sys/class/net/sc0/queues/tx-{q}/xps_cpus"),
            format!("{mask:x}"),
        );
    }
}

/// `tc -batch` of `lines` (one command per line).
fn tc_batch(lines: &str) {
    let path = std::env::temp_dir().join("shaper-root.tc");
    std::fs::write(&path, lines).unwrap();
    sh(&["tc", "-force", "-batch", path.to_str().unwrap()]);
}

/// HTB with `n` classes of `rate_bps` (fq_codel leaves) classified by
/// flower on the destination: under one root (`per_queue` false), or one
/// HTB per transmit queue of an `mq` root, each with every class.
fn htb(n: u32, rate_bps: u64, queues: u16, per_queue: bool) {
    let _ = sh_ok(&["tc", "qdisc", "del", "dev", "sc0", "root"]);
    let mut b = String::new();
    let roots: Vec<u32> = if per_queue {
        b.push_str("qdisc add dev sc0 root handle 1: mq\n");
        (0..u32::from(queues)).map(|q| 10 + q).collect()
    } else {
        vec![10]
    };
    let kbit = rate_bps / 1000;
    for (q, major) in roots.iter().enumerate() {
        let parent = if per_queue {
            format!("parent 1:{}", q + 1)
        } else {
            "root".into()
        };
        b.push_str(&format!(
            "qdisc add dev sc0 {parent} handle {major:x}: htb default 0 r2q 10\n"
        ));
        for i in 0..n {
            let minor = i + 1;
            b.push_str(&format!(
                "class add dev sc0 parent {major:x}: classid {major:x}:{minor:x} htb rate {kbit}kbit ceil {kbit}kbit\n"
            ));
            b.push_str(&format!(
                "qdisc add dev sc0 parent {major:x}:{minor:x} fq_codel\n"
            ));
            b.push_str(&format!(
                "filter add dev sc0 parent {major:x}: protocol ip prio 1 flower dst_ip {} classid {major:x}:{minor:x}\n",
                target(i)
            ));
        }
    }
    tc_batch(&b);
}

/// EDT against HTB at 1 000 and 10 000 targets: setup time, packets the
/// router gets through, CPU per packet, and the worst target's error.
/// Senders offer small packets as fast as they can (the router's cost is
/// per packet). 10 000 targets only with `COREROUTER_FULL_PERF=1`.
#[test]
fn perf_edt_vs_htb() {
    if !enabled() {
        return;
    }
    let queues = 4u16;
    let _lab = Lab::new(queues);
    // A sink: counted on the way in, dropped by the route (no local
    // delivery, no ICMP back).
    ns(
        CLIENT_NS,
        &["ip", "route", "del", "local", "10.70.0.0/16", "dev", "lo"],
    );
    ns(
        CLIENT_NS,
        &["ip", "route", "add", "blackhole", "10.70.0.0/16"],
    );
    steer(queues);
    let mut x = XdpState::default();
    let payload = 100usize;
    let ip_bytes = (payload + 28) as u64;
    // 10 000 targets take HTB's setup many minutes (40 000 classes with the
    // per-CPU trees): only on request (`COREROUTER_FULL_PERF=1`, the VM
    // lab), not on every CI run.
    let full = std::env::var_os("COREROUTER_FULL_PERF").is_some();
    let sizes: &[u32] = if full { &[1_000, 10_000] } else { &[1_000] };
    for &n in sizes {
        // Each target at a rate the VM can carry for all of them at once.
        let rate = 200_000_000u64 / u64::from(n) / 1000 * 1000;
        for case in ["edt", "htb one root", "htb per cpu"] {
            if n >= 10_000 && case == "htb per cpu" {
                // 40 000 classes + filters: `tc -batch` had not finished
                // after 23 minutes in the VM (2026-10-26, **medido**).
                println!("PERF | edt vs htb | {n} targets | {case} | setup over 23 min: not run");
                continue;
            }
            x.shaper_apply(&ShaperPlan::default()).unwrap();
            let _ = sh_ok(&["tc", "qdisc", "del", "dev", "sc0", "root"]);
            let t = Instant::now();
            match case {
                "edt" => {
                    let kind = if std::env::var_os("SHAPER_FIFO").is_some() {
                        fifo(rate, 100)
                    } else {
                        Kind::default()
                    };
                    x.shaper_apply(&download_plan(n, rate, kind)).unwrap()
                }
                "htb one root" => htb(n, rate, queues, false),
                _ => htb(n, rate, queues, true),
            }
            let setup = t.elapsed();
            // 1.5 × what the targets may take in all, paced: the router is
            // not the bottleneck of a saturated VM, the queues are.
            let fair = u64::from(n) * rate / (ip_bytes * 8);
            let pps = fair * 3 / 2;
            let secs = 6.0;
            let sender = std::thread::spawn(move || blast_paced(n, payload, secs, 4, pps));
            // Steady state: from second 2 (queues full) to the end.
            std::thread::sleep(Duration::from_secs(2));
            let (p0, c0, t0) = (rx_packets(CLIENT_NS, "sc1"), cpu_ticks(), Instant::now());
            let (sent, took) = sender.join().unwrap();
            let (p1, c1, dt) = (
                rx_packets(CLIENT_NS, "sc1"),
                cpu_ticks(),
                t0.elapsed().as_secs_f64(),
            );
            let delivered = p1.saturating_sub(p0);
            let cpus = std::thread::available_parallelism().map_or(1, |n| n.get()) as f64;
            // USER_HZ ticks (10 ms) of busy CPU over every core.
            let busy = (c1 - c0) as f64 / (dt * 100.0 * cpus) * 100.0;
            let err = delivered as f64 / dt / fair as f64 - 1.0;
            let st = x.shaper_status();
            let contended = st
                .stats
                .iter()
                .find(|(k, _)| *k == "contended")
                .map_or(0, |(_, v)| *v);
            println!(
                "PERF | edt vs htb | {n} targets × {:.0} kbit/s | {case} | setup {:.0} ms | offered {:.0} kpps | delivered {:.1} kpps of {:.1} ({:+.1}%) | busy CPU {busy:.1}% of {cpus} | contended {contended}",
                rate as f64 / 1e3,
                setup.as_secs_f64() * 1e3,
                sent as f64 / took / 1e3,
                delivered as f64 / dt / 1e3,
                fair as f64 / 1e3,
                err * 100.0,
            );
        }
    }
    x.shaper_apply(&ShaperPlan::default()).unwrap();
    let _ = sh_ok(&["tc", "qdisc", "del", "dev", "sc0", "root"]);
}

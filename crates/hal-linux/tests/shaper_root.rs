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
            "ip", "link", "add", "sc0", "numtxqueues", &q, "numrxqueues", &q, "type", "veth",
            "peer", "name", "sc1", "numtxqueues", &q, "numrxqueues", &q,
        ]);
        sh(&[
            "ip", "link", "add", "ss0", "numtxqueues", &q, "numrxqueues", &q, "type", "veth",
            "peer", "name", "ss1", "numtxqueues", &q, "numrxqueues", &q,
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
        ns(CLIENT_NS, &["ip", "addr", "add", "10.69.0.2/30", "dev", "sc1"]);
        ns(CLIENT_NS, &["ip", "link", "set", "sc1", "up"]);
        ns(CLIENT_NS, &["ip", "link", "set", "lo", "up"]);
        // Every address of 10.70.0.0/16 is this namespace's.
        ns(CLIENT_NS, &["ip", "route", "add", "local", "10.70.0.0/16", "dev", "lo"]);
        ns(CLIENT_NS, &["ip", "route", "add", "default", "via", "10.69.0.1"]);
        ns(SERVER_NS, &["ip", "addr", "add", "10.68.0.2/30", "dev", "ss1"]);
        ns(SERVER_NS, &["ip", "link", "set", "ss1", "up"]);
        ns(SERVER_NS, &["ip", "link", "set", "lo", "up"]);
        ns(SERVER_NS, &["ip", "route", "add", "default", "via", "10.68.0.1"]);
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
        p.prefixes.push((IpNet::from(std::net::IpAddr::V4(target(i))), i));
    }
    p
}

/// Count IP bytes per destination arriving on `sc1` until `stop`, then
/// `drain` more.
fn receiver(stop: Arc<AtomicBool>, drain: Duration) -> std::thread::JoinHandle<HashMap<Ipv4Addr, u64>> {
    Lab::spawn_in(CLIENT_NS, move || {
        let sock = socket2::Socket::new(
            socket2::Domain::PACKET,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::from(i32::from(0x0800u16.to_be()))),
        )
        .unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        // Root: past `rmem_max` (a drop here would read as a shaper error).
        let _ = nix::sys::socket::setsockopt(&sock, nix::sys::socket::sockopt::RcvBufForce, &(256 << 20));
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
    let handles: Vec<_> = (0..threads)
        .map(|t| {
            Lab::spawn_in(SERVER_NS, move || {
                let s = UdpSocket::bind(("10.68.0.2", 20_000 + t as u16)).unwrap();
                let data = vec![0u8; payload];
                let start = Instant::now();
                let mut sent = 0u64;
                let mut i = t;
                while start.elapsed().as_secs_f64() < secs {
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
    assert_eq!(st.ports.iter().map(|p| p.as_str()).collect::<Vec<_>>(), ["sc0"]);
    assert_eq!(st.queues.len(), 10);
    let q = sh(&["tc", "qdisc", "show", "dev", "sc0"]);
    assert!(q.contains("qdisc fq"), "{q}");
    // Traffic to a target is shaped (counted by its queue).
    ns(SERVER_NS, &["ping", "-c", "3", "-i", "0.2", "-W", "2", "10.70.0.1"]);
    let st = x.shaper_status();
    let (_, c) = st.queues.iter().find(|(k, _)| k == "q1").unwrap();
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
    for (n, top_bps) in [(1u32, 1_000_000_000u64), (100, 20_000_000), (10_000, 200_000)] {
        // 10 000 targets share what the VM forwards (~300 Mbit/s in a debug
        // build): small packets keep each target at hundreds of packets.
        let payload = if n >= 10_000 { 100usize } else { 1000 };
        let ip_bytes = (payload + 28) as u64;
        let mut rate = top_bps;
        // Enough packets per target that one is under 1% of its total.
        let secs = if n >= 10_000 { 8.0 } else { 3.0 };
        for round in 0..4 {
            x.shaper_apply(&ShaperPlan::default()).unwrap();
            x.shaper_apply(&download_plan(n, rate, fifo(rate, 20))).unwrap();
            let stop = Arc::new(AtomicBool::new(false));
            let rx = receiver(stop.clone(), Duration::from_millis(300));
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
            assert!(offered_min >= 2.0 * rate as f64, "{n} targets: not offered enough");
            assert!(worst.abs() <= 0.05, "{n} targets: worst {worst:+.3}");
            break;
        }
    }
}

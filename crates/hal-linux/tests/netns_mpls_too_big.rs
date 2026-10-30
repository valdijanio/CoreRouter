//! G3.9da — Path MTU Discovery through an LSP with a smaller link in the
//! middle, and the per-source ICMP rate limit, against real kernels in
//! throwaway network namespaces — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_mpls_too_big -- --nocapture
//! ```
//!
//! ```text
//!  this ns (A)       CR1 (ingress)        CR2 (LSR, our responder)     CR3 (PHP)            B
//!  ma0 ──────── mb0     mc1 ────────── mc2      md2 ═════════════ md3     me3 ──────── me4
//!  10.71.0.1/24          10.72.0.1/24  10.72.0.2  10.73.0.1   MTU 1400   10.73.0.2    10.74.0.2
//!  10.71.0.3/24  push 100 (v6: 101)    swap 100→200 (101→201)   pop 200, 201
//!  fd71::1/64            fd72::1/64    fd72::2    fd73::1                fd73::2      fd74::2
//! ```
//!
//! A packet of 1450 octets with DF reaches CR2 with one label; the swap
//! keeps one label on, so 1450 + 4 does not fit md2's 1400: the kernel
//! drops it with no error (`mpls_forward`, `mpls_pkt_too_big`), and PMTUD
//! black-holes. With the responder on `mc2`, A gets "fragmentation needed"
//! (IPv6: "packet too big") with MTU 1396 from 10.72.0.2, and a probe of
//! 1396 then reaches B. The flood test sends TTL 2 from 10.71.0.1 (expiring
//! at CR2) while 10.71.0.3 traces, with and without the per-source limit.
//!
//! CR1, CR2, CR3 and B are nested namespaces (`unshare --net sleep`); the
//! responder runs on a thread moved into CR2's (`setns`), as the daemon's
//! `lsp-ping` service would there. Needs `mpls_router` and `mpls_iptunnel`
//! (the CI and the lab VM load them); without them it skips, unless
//! `COREROUTER_REQUIRE_MPLS=1`.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_hal::lsp::rate::IcmpLimit;
use corerouter_hal::lsp::{Frame, LspResponderIo, expired, too_big};
use corerouter_hal::probe::{Probe, ProbeSocket, Prober, Reply, ReplyKind, SocketOptions};
use corerouter_hal_linux::icmp::{HostProber, Kind};
use corerouter_hal_linux::lsp::HostResponder;
use corerouter_hal_linux::mpls::available;
use nix::sched::{CloneFlags, setns};

const ENV: &str = "COREROUTER_NETNS_TESTS";
const REQUIRE: &str = "COREROUTER_REQUIRE_MPLS";
static ONE: Mutex<()> = Mutex::new(());

const B4: &str = "10.74.0.2";
const B6: &str = "fd74::2";

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
        .map(str::trim)
        .map(|n| n.split('@').next().unwrap_or(n))
        .collect();
    assert!(
        names.iter().all(|n| *n == "lo" || n.starts_with("ma")),
        "{ENV}=1 but this namespace has {names:?}; refusing to touch it"
    );
    true
}

fn mpls_here() -> bool {
    if available() && std::path::Path::new("/proc/sys/net/mpls/platform_labels").exists() {
        return true;
    }
    assert!(
        std::env::var_os(REQUIRE).is_none_or(|v| v != "1"),
        "{REQUIRE}=1 but mpls_router is not loaded"
    );
    eprintln!("skipped: no kernel MPLS (modprobe mpls_router mpls_iptunnel)");
    false
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{cmd:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn ip(args: &[&str]) -> String {
    run(Command::new("ip").args(args))
}

fn sysctl(path: &str, value: &str) {
    std::fs::write(format!("/proc/sys/{path}"), value).unwrap();
}

/// A nested network namespace, alive while this value is.
struct Ns(Child);

impl Ns {
    fn new() -> Self {
        let child = Command::new("unshare")
            .args(["--net", "--", "sleep", "600"])
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let ns = Ns(child);
        let mine = std::fs::read_link("/proc/self/ns/net").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while std::fs::read_link(format!("/proc/{}/ns/net", ns.pid())).ok() == Some(mine.clone()) {
            assert!(Instant::now() < deadline, "unshare --net did not start");
            thread::sleep(Duration::from_millis(10));
        }
        ns.ip(&["link", "set", "lo", "up"]);
        ns
    }

    fn pid(&self) -> String {
        self.0.id().to_string()
    }

    fn ip(&self, args: &[&str]) -> String {
        let pid = self.pid();
        run(Command::new("nsenter")
            .args(["-t", pid.as_str(), "-n", "ip"])
            .args(args))
    }

    fn sysctl(&self, path: &str, value: &str) {
        let pid = self.pid();
        let script = format!("echo {value} > /proc/sys/{path}");
        run(Command::new("nsenter").args(["-t", pid.as_str(), "-n", "sh", "-c", script.as_str()]));
    }
}

impl Drop for Ns {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Lab {
    _cr1: Ns,
    cr2: Ns,
    _cr3: Ns,
    _b: Ns,
}

fn veth(from: Option<&Ns>, a: &str, b: &str, to: &Ns) {
    let args = [
        "link",
        "add",
        a,
        "type",
        "veth",
        "peer",
        "name",
        b,
        "netns",
        &to.pid(),
    ];
    match from {
        Some(ns) => ns.ip(&args),
        None => ip(&args),
    };
}

/// The topology of the module docs.
fn lab() -> Lab {
    let _ = Command::new("ip").args(["link", "del", "ma0"]).output();
    let (cr1, cr2, cr3, b) = (Ns::new(), Ns::new(), Ns::new(), Ns::new());
    veth(None, "ma0", "mb0", &cr1);
    veth(Some(&cr1), "mc1", "mc2", &cr2);
    veth(Some(&cr2), "md2", "md3", &cr3);
    veth(Some(&cr3), "me3", "me4", &b);

    for a in ["10.71.0.1/24", "10.71.0.3/24"] {
        ip(&["addr", "add", a, "dev", "ma0"]);
    }
    ip(&["addr", "add", "fd71::1/64", "dev", "ma0", "nodad"]);
    ip(&["link", "set", "ma0", "up"]);
    ip(&["route", "replace", "10.64.0.0/12", "via", "10.71.0.2"]);
    ip(&["-6", "route", "replace", "fd70::/12", "via", "fd71::2"]);
    sysctl("net/ipv4/icmp_ratelimit", "0");

    for (ns, devs) in [
        (&cr1, ["mb0", "mc1"]),
        (&cr2, ["mc2", "md2"]),
        (&cr3, ["md3", "me3"]),
        (&b, ["me4", "me4"]),
    ] {
        ns.sysctl("net/ipv4/ip_forward", "1");
        ns.sysctl("net/ipv6/conf/all/forwarding", "1");
        ns.sysctl("net/ipv4/icmp_ratelimit", "0");
        ns.sysctl("net/mpls/platform_labels", "1000");
        for d in devs {
            ns.ip(&["link", "set", d, "up"]);
            ns.sysctl(&format!("net/mpls/conf/{d}/input"), "1");
        }
    }
    // The small link in the middle of the LSP.
    cr2.ip(&["link", "set", "md2", "mtu", "1400"]);
    cr3.ip(&["link", "set", "md3", "mtu", "1400"]);
    for (ns, dev, v4, v6) in [
        (&cr1, "mb0", "10.71.0.2/24", "fd71::2/64"),
        (&cr1, "mc1", "10.72.0.1/24", "fd72::1/64"),
        (&cr2, "mc2", "10.72.0.2/24", "fd72::2/64"),
        (&cr2, "md2", "10.73.0.1/24", "fd73::1/64"),
        (&cr3, "md3", "10.73.0.2/24", "fd73::2/64"),
        (&cr3, "me3", "10.74.0.1/24", "fd74::1/64"),
        (&b, "me4", "10.74.0.2/24", "fd74::2/64"),
    ] {
        ns.ip(&["addr", "add", v4, "dev", dev]);
        ns.ip(&["addr", "add", v6, "dev", dev, "nodad"]);
    }

    // The LSPs to B: CR1 pushes, CR2 swaps (one label stays on), CR3 pops.
    cr1.ip(&[
        "route",
        "add",
        &format!("{B4}/32"),
        "encap",
        "mpls",
        "100",
        "via",
        "10.72.0.2",
    ]);
    cr1.ip(&[
        "-6",
        "route",
        "add",
        &format!("{B6}/128"),
        "encap",
        "mpls",
        "101",
        "via",
        "fd72::2",
    ]);
    cr2.ip(&[
        "-f",
        "mpls",
        "route",
        "add",
        "100",
        "as",
        "200",
        "via",
        "inet",
        "10.73.0.2",
        "dev",
        "md2",
    ]);
    cr2.ip(&[
        "-f", "mpls", "route", "add", "101", "as", "201", "via", "inet6", "fd73::2", "dev", "md2",
    ]);
    cr3.ip(&[
        "-f", "mpls", "route", "add", "200", "via", "inet", B4, "dev", "me3",
    ]);
    cr3.ip(&[
        "-f", "mpls", "route", "add", "201", "via", "inet6", B6, "dev", "me3",
    ]);
    // CR2's way to B by IP: rp_filter drops B's answers on md2 without it.
    cr2.ip(&["route", "add", "10.74.0.0/24", "via", "10.73.0.2"]);
    cr2.ip(&["-6", "route", "add", "fd74::/64", "via", "fd73::2"]);
    // Back to A by IP.
    for (ns, v4, v6) in [
        (&cr2, "10.72.0.1", "fd72::1"),
        (&cr3, "10.73.0.1", "fd73::1"),
        (&b, "10.74.0.1", "fd74::1"),
    ] {
        ns.ip(&["route", "add", "10.71.0.0/24", "via", v4]);
        ns.ip(&["-6", "route", "add", "fd71::/64", "via", v6]);
    }
    Lab {
        _cr1: cr1,
        cr2,
        _cr3: cr3,
        _b: b,
    }
}

/// What the responder did.
#[derive(Debug, Default)]
struct Done {
    too_big_sent: u64,
    expired_sent: u64,
    refused: u64,
    last_err: Option<String>,
    tap: String,
}

/// The responder in CR2's namespace on `mc2`, behind the limits the
/// daemon's service uses, until `stop`.
fn responder(
    cr2: &Ns,
    stop: Arc<AtomicBool>,
    rate: u32,
    per_source: u32,
) -> thread::JoinHandle<Done> {
    let ns = std::fs::File::open(format!("/proc/{}/ns/net", cr2.pid())).unwrap();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let h = thread::Builder::new()
        .name("cr2-responder".into())
        .spawn(move || {
            setns(&ns, CloneFlags::CLONE_NEWNET).unwrap();
            let mut r = HostResponder::open().unwrap();
            let failed = r.set_interfaces(&["mc2".parse().unwrap()]);
            assert!(failed.is_empty(), "{failed:?}");
            r.hear_too_big(true);
            ready_tx.send(()).unwrap();
            let mut limit = IcmpLimit::new(rate, per_source, Instant::now());
            let mut done = Done::default();
            while !stop.load(Ordering::Relaxed) {
                let frame = match r.recv(Duration::from_millis(50)).unwrap() {
                    Some(f @ (Frame::Expired(_) | Frame::TooBig(_))) => f,
                    _ => continue,
                };
                let to = match &frame {
                    Frame::Expired(e) => expired::origin(&e.packet),
                    Frame::TooBig(t) => too_big::origin(t),
                    Frame::Echo(_) => None,
                };
                if limit.take(to, Instant::now()).is_err() {
                    done.refused += 1;
                    continue;
                }
                let a = match &frame {
                    Frame::Expired(e) => expired::answer(e, r.view()),
                    Frame::TooBig(t) => too_big::answer(t, r.view()),
                    Frame::Echo(_) => continue,
                };
                match a.map(|a| r.send_icmp(&a)) {
                    Ok(Ok(())) if matches!(frame, Frame::TooBig(_)) => done.too_big_sent += 1,
                    Ok(Ok(())) => done.expired_sent += 1,
                    // ARP for the next hop on the first try.
                    Ok(Err(e)) => done.last_err = Some(e.to_string()),
                    Err(why) => done.last_err = Some(why.to_owned()),
                }
            }
            done.tap = r.tap_kind();
            eprintln!("tap: {}", done.tap);
            done
        })
        .unwrap();
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    h
}

fn opts(src: Option<&str>) -> SocketOptions {
    SocketOptions {
        dont_fragment: true,
        src: src.map(|s| s.parse().unwrap()),
        ..SocketOptions::default()
    }
}

/// One probe and its answer within `wait`.
fn probe(
    sock: &mut dyn ProbeSocket,
    dst: &str,
    seq: u16,
    ttl: u8,
    size: u16,
    wait: Duration,
) -> Option<Reply> {
    sock.send(&Probe {
        dst: dst.parse().unwrap(),
        seq,
        ttl: Some(ttl),
        size,
    })
    .unwrap();
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        if let Some(r) = sock.recv(Duration::from_millis(50)).unwrap()
            && r.seq == seq
        {
            return Some(r);
        }
    }
    None
}

/// A few tries (ARP and ND on fresh links).
fn tries(sock: &mut dyn ProbeSocket, dst: &str, seq: u16, size: u16) -> Option<Reply> {
    (0..5).find_map(|i| probe(sock, dst, seq + i, 64, size, Duration::from_millis(700)))
}

fn path_mtu(dst: &str, from: &str, base: u16) {
    let lab = lab();
    let prober = HostProber::with_kind(Kind::Raw);
    let mut sock = prober.open(&opts(None)).unwrap();
    // Small packets cross the LSP.
    let r = tries(sock.as_mut(), dst, base, 1000).expect("B answers through the LSP");
    assert_eq!(r.kind, ReplyKind::Echo);
    // The bug: too big for md2, the kernel drops it and says nothing.
    assert_eq!(
        probe(
            sock.as_mut(),
            dst,
            base + 10,
            64,
            1450,
            Duration::from_millis(700)
        ),
        None,
        "the kernel alone sends no ICMP"
    );
    // The fix.
    let stop = Arc::new(AtomicBool::new(false));
    let worker = responder(&lab.cr2, stop.clone(), 100, 10);
    let r = tries(sock.as_mut(), dst, base + 20, 1450);
    stop.store(true, Ordering::Relaxed);
    let done = worker.join().unwrap();
    let r = r.unwrap_or_else(|| {
        panic!(
            "no ICMP from CR2: {done:?}\n{}{}",
            lab.cr2.ip(&["-f", "mpls", "route"]),
            lab.cr2.ip(&["-br", "link"])
        )
    });
    // RFC 3032 §3.4–3.5: 1400 minus the one label that leaves.
    assert_eq!(r.kind, ReplyKind::TooBig { mtu: Some(1396) }, "{done:?}");
    assert_eq!(
        r.from,
        from.parse::<IpAddr>().unwrap(),
        "the incoming link's address"
    );
    if !r.from.is_ipv6() {
        // RFC 4950: the stack as it arrived at CR2 (CR1 copied IP TTL 64).
        assert_eq!(
            r.mpls.iter().map(|l| (l.label, l.ttl)).collect::<Vec<_>>(),
            [(100, 63)]
        );
    }
    assert!(done.too_big_sent >= 1);
    // The MTU it said is the one that fits: 1396 reaches B.
    let r = tries(sock.as_mut(), dst, base + 30, 1396).expect("1396 octets reach B");
    assert_eq!(r.kind, ReplyKind::Echo);
}

#[test]
fn path_mtu_discovery_through_the_lsp_ipv4() {
    let _one = ONE.lock().unwrap_or_else(|p| p.into_inner());
    if !in_netns() || !mpls_here() {
        return;
    }
    path_mtu(B4, "10.72.0.2", 1000);
}

#[test]
fn path_mtu_discovery_through_the_lsp_ipv6() {
    let _one = ONE.lock().unwrap_or_else(|p| p.into_inner());
    if !in_netns() || !mpls_here() {
        return;
    }
    path_mtu(B6, "fd72::2", 2000);
}

/// Of 20 traceroute probes from 10.71.0.3 (one every 100 ms) expiring at
/// CR2 while 10.71.0.1 floods TTL 2 at `pps`, how many CR2 answered.
fn traced_under_flood(per_source: u32, pps: u32) -> (usize, Done) {
    let lab = lab();
    let prober = HostProber::with_kind(Kind::Raw);
    let mut warm = prober.open(&opts(None)).unwrap();
    tries(warm.as_mut(), B4, 100, 100).expect("B answers through the LSP");
    let stop = Arc::new(AtomicBool::new(false));
    let worker = responder(&lab.cr2, stop.clone(), 100, per_source);
    let flooding = Arc::new(AtomicBool::new(true));
    let flood = {
        let flooding = flooding.clone();
        let mut sock = prober.open(&opts(Some("10.71.0.1"))).unwrap();
        thread::Builder::new()
            .name("flood".into())
            .spawn(move || {
                let gap = Duration::from_secs(1) / pps;
                let mut next = Instant::now();
                let mut seq = 10_000u16;
                while flooding.load(Ordering::Relaxed) {
                    let _ = sock.send(&Probe {
                        dst: B4.parse().unwrap(),
                        seq,
                        ttl: Some(2),
                        size: 64,
                    });
                    // Read what came back, so the socket does not fill.
                    while let Ok(Some(_)) = sock.recv(Duration::ZERO) {}
                    seq = seq.wrapping_add(1).max(10_000);
                    next += gap;
                    thread::sleep(next.saturating_duration_since(Instant::now()));
                }
            })
            .unwrap()
    };
    thread::sleep(Duration::from_millis(300));
    let mut trace = prober.open(&opts(Some("10.71.0.3"))).unwrap();
    // 5 probes a second, under the tracer's own 10/s (a traceroute sends
    // three a hop); back to back, its own bucket would refuse some.
    let answered = (0..20u16)
        .filter(|i| {
            let at = Instant::now();
            let r = probe(
                trace.as_mut(),
                B4,
                500 + i,
                2,
                64,
                Duration::from_millis(100),
            );
            thread::sleep(Duration::from_millis(200).saturating_sub(at.elapsed()));
            r.is_some_and(|r| r.kind == ReplyKind::TtlExceeded)
        })
        .count();
    flooding.store(false, Ordering::Relaxed);
    flood.join().unwrap();
    stop.store(true, Ordering::Relaxed);
    (answered, worker.join().unwrap())
}

/// The per-source limit: a host flooding TTL 1 at CR2 no longer hides the
/// hop from everyone else's traceroute (G3.9da).
#[test]
fn a_flood_from_one_source_does_not_hide_the_hop_from_another() {
    let _one = ONE.lock().unwrap_or_else(|p| p.into_inner());
    if !in_netns() || !mpls_here() {
        return;
    }
    let pps = 2000;
    // Off (as before G3.9da): the flood takes the global 100/s.
    let (off, d_off) = traced_under_flood(10_000, pps);
    let (on, d_on) = traced_under_flood(10, pps);
    eprintln!(
        "flood {pps} pps of TTL 2 from 10.71.0.1; traced from 10.71.0.3: without the per-source limit {off}/20 ({d_off:?}), with 10/s per source {on}/20 ({d_on:?})"
    );
    assert!(on >= 18, "with the per-source limit: {on}/20 ({d_on:?})");
    assert!(off < on, "without: {off}/20, with: {on}/20");
}

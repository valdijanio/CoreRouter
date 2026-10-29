//! G3.9d — traceroute through an LSP: the transit LSR where the label TTL
//! expires answers with ICMP time exceeded and the RFC 4950 label stack,
//! against real kernels in throwaway network namespaces — no root, nothing
//! reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_mpls_ttl
//! ```
//!
//! ```text
//!  this ns (A)        CR1 (ingress LER)          CR2 (LSR, our responder)          B
//!  ma0 ─────────── mb0      mc1 ─────────────── mc2      md2 ─────────────── md3
//!  10.61.0.1/24    10.61.0.2  10.62.0.1/24      10.62.0.2  10.63.0.1/24      10.63.0.2/24
//!                  push 100 for 10.63.0.2/32    label 100: pop to 10.63.0.2
//! ```
//!
//! A traceroute to B with TTL 2 reaches CR2 with label TTL 1: the kernel
//! drops it without an error (`*`); with the responder's taps on `mc2`,
//! CR2 answers from 10.62.0.2 with label 100 in the extension. Two ways
//! back (RFC 3032 §2.3.2):
//!
//! - CR2 has an IP route to A: the error goes by the IP table;
//! - CR2 has none (a BGP-free core): the error follows the LSP to B, the
//!   egress, which routes it back to A over its own LSP (label 300 at CR2,
//!   popped towards CR1).
//!
//! CR1, CR2 and B are nested namespaces (`unshare --net sleep`); the
//! responder runs on a thread moved into CR2's (`setns`), as the daemon's
//! `lsp-ping` service would there. Needs `mpls_router` and
//! `mpls_iptunnel` (the CI and the lab VM load them); without them it
//! skips, unless `COREROUTER_REQUIRE_MPLS=1`.
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

use corerouter_hal::lsp::expired::answer;
use corerouter_hal::lsp::{Frame, LspResponderIo};
use corerouter_hal::probe::{
    MplsLabel, Probe, ProbeSocket, Prober, Reply, ReplyKind, SocketOptions,
};
use corerouter_hal_linux::icmp::{HostProber, Kind};
use corerouter_hal_linux::lsp::HostResponder;
use corerouter_hal_linux::mpls::available;
use nix::sched::{CloneFlags, setns};

const ENV: &str = "COREROUTER_NETNS_TESTS";
const REQUIRE: &str = "COREROUTER_REQUIRE_MPLS";
static ONE: Mutex<()> = Mutex::new(());

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

/// Kernel MPLS here (the module is the host's)?
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
    b: Ns,
}

const B: &str = "10.63.0.2";

/// The topology of the module docs. `route_back`: CR2 has an IP route to
/// A; without it, B returns traffic to A over label 300.
fn lab(route_back: bool) -> Lab {
    let _ = Command::new("ip").args(["link", "del", "ma0"]).output();
    let (cr1, cr2, b) = (Ns::new(), Ns::new(), Ns::new());
    ip(&[
        "link",
        "add",
        "ma0",
        "type",
        "veth",
        "peer",
        "name",
        "mb0",
        "netns",
        &cr1.pid(),
    ]);
    cr1.ip(&[
        "link",
        "add",
        "mc1",
        "type",
        "veth",
        "peer",
        "name",
        "mc2",
        "netns",
        &cr2.pid(),
    ]);
    cr2.ip(&[
        "link",
        "add",
        "md2",
        "type",
        "veth",
        "peer",
        "name",
        "md3",
        "netns",
        &b.pid(),
    ]);

    ip(&["addr", "add", "10.61.0.1/24", "dev", "ma0"]);
    ip(&["link", "set", "ma0", "up"]);
    ip(&["route", "replace", "10.60.0.0/14", "via", "10.61.0.2"]);

    for (ns, devs) in [
        (&cr1, ["mb0", "mc1"]),
        (&cr2, ["mc2", "md2"]),
        (&b, ["md3", "md3"]),
    ] {
        ns.sysctl("net/ipv4/ip_forward", "1");
        ns.sysctl("net/mpls/platform_labels", "1000");
        for d in devs {
            ns.ip(&["link", "set", d, "up"]);
            ns.sysctl(&format!("net/mpls/conf/{d}/input"), "1");
        }
    }
    cr1.ip(&["addr", "add", "10.61.0.2/24", "dev", "mb0"]);
    cr1.ip(&["addr", "add", "10.62.0.1/24", "dev", "mc1"]);
    cr2.ip(&["addr", "add", "10.62.0.2/24", "dev", "mc2"]);
    cr2.ip(&["addr", "add", "10.63.0.1/24", "dev", "md2"]);
    b.ip(&["addr", "add", "10.63.0.2/24", "dev", "md3"]);

    // The LSP to B: CR1 pushes 100 (the IP TTL copied into it), CR2 pops.
    cr1.ip(&[
        "route",
        "add",
        &format!("{B}/32"),
        "encap",
        "mpls",
        "100",
        "via",
        "10.62.0.2",
    ]);
    cr2.ip(&[
        "-f", "mpls", "route", "add", "100", "via", "inet", B, "dev", "md2",
    ]);
    // Back to A.
    if route_back {
        cr2.ip(&["route", "add", "10.61.0.0/24", "via", "10.62.0.1"]);
        b.ip(&["route", "add", "default", "via", "10.63.0.1"]);
    } else {
        // A BGP-free core: only the egress knows A, over an LSP of its own.
        b.ip(&[
            "route",
            "add",
            "10.61.0.0/24",
            "encap",
            "mpls",
            "300",
            "via",
            "10.63.0.1",
        ]);
        cr2.ip(&[
            "-f",
            "mpls",
            "route",
            "add",
            "300",
            "via",
            "inet",
            "10.62.0.1",
            "dev",
            "mc2",
        ]);
    }
    Lab { _cr1: cr1, cr2, b }
}

/// The responder in CR2's namespace on `mc2`: hears expired labeled
/// packets and sends the errors, until `stop`. Returns how many it sent.
fn responder(cr2: &Ns, stop: Arc<AtomicBool>) -> thread::JoinHandle<u64> {
    let ns = std::fs::File::open(format!("/proc/{}/ns/net", cr2.pid())).unwrap();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let h = thread::Builder::new()
        .name("cr2-responder".into())
        .spawn(move || {
            setns(&ns, CloneFlags::CLONE_NEWNET).unwrap();
            let mut r = HostResponder::open().unwrap();
            let failed = r.set_interfaces(&["mc2".parse().unwrap()]);
            assert!(failed.is_empty(), "{failed:?}");
            ready_tx.send(()).unwrap();
            let mut sent = 0;
            let mut last_err = None;
            while !stop.load(Ordering::Relaxed) {
                let Some(Frame::Expired(e)) = r.recv(Duration::from_millis(50)).unwrap() else {
                    continue;
                };
                match answer(&e, r.view()) {
                    Ok(a) => match r.send_icmp(&a) {
                        Ok(()) => sent += 1,
                        // ARP for the next hop on the first try.
                        Err(e) => last_err = Some(e.to_string()),
                    },
                    Err(why) => last_err = Some(why.to_owned()),
                }
            }
            if sent == 0 {
                eprintln!("responder sent nothing; last error: {last_err:?}");
            }
            sent
        })
        .unwrap();
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    h
}

fn probe(sock: &mut dyn ProbeSocket, seq: u16, ttl: u8) -> Option<Reply> {
    sock.send(&Probe {
        dst: B.parse().unwrap(),
        seq,
        ttl: Some(ttl),
        size: 64,
    })
    .unwrap();
    let deadline = Instant::now() + Duration::from_millis(700);
    while Instant::now() < deadline {
        if let Some(r) = sock.recv(Duration::from_millis(100)).unwrap()
            && r.seq == seq
        {
            return Some(r);
        }
    }
    None
}

/// A few tries (ARP on fresh links, the responder's first neighbor miss).
fn trace_hop(sock: &mut dyn ProbeSocket, seq: u16, ttl: u8) -> Option<Reply> {
    (0..5).find_map(|i| probe(sock, seq + i, ttl))
}

fn traceroute(route_back: bool, base: u16) {
    let lab = lab(route_back);
    let prober = HostProber::with_kind(Kind::Raw);
    let mut sock = prober.open(&SocketOptions::default()).unwrap();
    // The path works end to end: B answers at TTL 3.
    let r = trace_hop(sock.as_mut(), base, 3).expect("B answers through the LSP");
    assert_eq!(
        (r.kind.clone(), r.from),
        (ReplyKind::Echo, B.parse::<IpAddr>().unwrap())
    );
    let r = trace_hop(sock.as_mut(), base + 10, 1).expect("CR1 answers");
    assert_eq!(r.kind, ReplyKind::TtlExceeded);
    assert_eq!(r.from, "10.61.0.2".parse::<IpAddr>().unwrap());
    // The bug: the label TTL expires at CR2, the kernel says nothing.
    assert_eq!(
        probe(sock.as_mut(), base + 20, 2),
        None,
        "the kernel alone sends no ICMP"
    );
    // The fix.
    let stop = Arc::new(AtomicBool::new(false));
    let worker = responder(&lab.cr2, stop.clone());
    let r = trace_hop(sock.as_mut(), base + 30, 2);
    stop.store(true, Ordering::Relaxed);
    let sent = worker.join().unwrap();
    let r = r.unwrap_or_else(|| {
        panic!(
            "no ICMP from CR2 (sent {sent}); CR2: {} B: {}",
            lab.cr2.ip(&["-s", "link", "show", "mc2"]),
            lab.b.ip(&["route"])
        )
    });
    assert_eq!(r.kind, ReplyKind::TtlExceeded);
    assert_eq!(
        r.from,
        "10.62.0.2".parse::<IpAddr>().unwrap(),
        "the incoming link's address"
    );
    // RFC 4950: the stack as it arrived at CR2.
    assert_eq!(
        r.mpls,
        vec![MplsLabel {
            label: 100,
            tc: 0,
            bottom: true,
            ttl: 1
        }]
    );
    assert!(sent >= 1);
}

#[test]
fn traceroute_through_the_lsp_by_the_ip_table() {
    let _one = ONE.lock().unwrap_or_else(|p| p.into_inner());
    if !in_netns() || !mpls_here() {
        return;
    }
    traceroute(true, 1000);
}

#[test]
fn traceroute_through_a_bgp_free_core_follows_the_lsp() {
    let _one = ONE.lock().unwrap_or_else(|p| p.into_inner());
    if !in_netns() || !mpls_here() {
        return;
    }
    traceroute(false, 2000);
}

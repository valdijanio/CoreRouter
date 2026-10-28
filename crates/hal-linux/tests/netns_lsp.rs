//! G3.5b — LSP ping through our own sockets against a real kernel, inside
//! a throwaway network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_lsp
//! ```
//!
//! One namespace, a veth pair `lpa`/`lpb`: requests leave `lpa` as whole
//! frames to a fake next hop whose static neighbor entry is `lpb`'s MAC,
//! the responder hears them on `lpb`, and its reply comes back as UDP to
//! the sender's port (both ends are local here). Without `mpls_router`
//! only the unlabeled path runs (the egress after PHP); with it (the CI,
//! the VM) the labeled one too: a TTL that expires at a transit LSR.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_hal::lsp::respond::{Verdict, ddmap_of, respond};
use corerouter_hal::lsp::wire::{self, Echo, Fec, code};
use corerouter_hal::lsp::{LspPath, LspRequest, LspResponderIo, LspSocket, destination};
use corerouter_hal::mpls::{MplsNexthop, Origin};
use corerouter_hal_linux::lsp::{HostLspSocket, HostResponder};
use corerouter_hal_linux::mpls::available;

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
        names.iter().all(|n| *n == "lo" || n.starts_with("lp")),
        "{ENV}=1 but this namespace has {names:?}; refusing to touch it"
    );
    true
}

fn ip(args: &[&str]) -> String {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// The MAC of `dev` (from `ip`: this namespace's /sys is the host's).
fn mac(dev: &str) -> String {
    let out = ip(&["-o", "link", "show", dev]);
    let at = out.find("link/ether ").unwrap() + "link/ether ".len();
    out[at..at + 17].to_owned()
}

/// `lpa` 10.77.0.1/24 — `lpb` 10.77.0.2/24; the fake next hop 10.77.0.9
/// on `lpa` is `lpb`'s MAC.
fn setup() {
    let _ = Command::new("ip").args(["link", "del", "lpa"]).output();
    ip(&["link", "add", "lpa", "type", "veth", "peer", "name", "lpb"]);
    ip(&["addr", "add", "10.77.0.1/24", "dev", "lpa"]);
    ip(&["addr", "add", "10.77.0.2/24", "dev", "lpb"]);
    ip(&["link", "set", "lpa", "up"]);
    ip(&["link", "set", "lpb", "up"]);
    ip(&["link", "set", "lo", "up"]);
    let m = mac("lpb");
    ip(&[
        "neigh",
        "replace",
        "10.77.0.9",
        "lladdr",
        &m,
        "dev",
        "lpa",
        "nud",
        "permanent",
    ]);
    ip(&[
        "route",
        "replace",
        "10.255.7.7/32",
        "via",
        "10.77.0.9",
        "dev",
        "lpa",
        "onlink",
    ]);
}

/// The responder on `lpb`, answering until `stop`.
fn responder(stop: Arc<AtomicBool>) -> thread::JoinHandle<u64> {
    let mut r = HostResponder::open().unwrap();
    let failed = r.set_interfaces(&["lpb".parse().unwrap()]);
    assert!(failed.is_empty(), "{failed:?}");
    thread::Builder::new()
        .name("lsp-responder".into())
        .spawn(move || {
            let mut replied = 0;
            while !stop.load(Ordering::Relaxed) {
                let Some(h) = r.recv(Duration::from_millis(50)).unwrap() else {
                    continue;
                };
                let ntp = r.now_ntp();
                if let Verdict::Reply {
                    to,
                    from,
                    tos,
                    payload,
                    ..
                } = respond(&h, r.view(), ntp)
                {
                    r.send(to, from, tos, &payload).unwrap();
                    replied += 1;
                }
            }
            replied
        })
        .unwrap()
}

fn ask(s: &mut HostLspSocket, path: &LspPath, e: &Echo, ttl: u8) -> (Echo, IpAddr, Duration) {
    let payload = wire::encode(e);
    s.send(&LspRequest {
        path,
        ttl,
        dst: destination(false, 1),
        tos: 0,
        payload: &payload,
    })
    .unwrap();
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        if let Some(a) = s.recv(Duration::from_millis(100)).unwrap() {
            let r = wire::parse(&a.payload).unwrap();
            if r.seq == e.seq {
                return (r, a.from, a.rtt.unwrap());
            }
        }
    }
    panic!("no reply to seq {}", e.seq);
}

#[test]
fn unlabeled_requests_reach_the_egress() {
    let _one = ONE.lock().unwrap_or_else(|p| p.into_inner());
    if !in_netns() {
        return;
    }
    setup();
    let stop = Arc::new(AtomicBool::new(false));
    let worker = responder(stop.clone());
    let mut s = HostLspSocket::open().unwrap();
    // The route of the FEC, as the kernel has it: no labels (PHP).
    let paths = s.paths("10.255.7.7/32".parse().unwrap()).unwrap();
    assert_eq!(paths.len(), 1, "{paths:?}");
    let p = &paths[0];
    assert!(p.labels.is_empty());
    assert_eq!(p.nexthop, Some("10.77.0.9".parse().unwrap()));
    assert_eq!(p.interface.as_str(), "lpa");
    assert_eq!(p.src, Some("10.77.0.1".parse().unwrap()));
    // 10.255.7.7 is nobody's: the LSR where it ends says "no mapping".
    let (r, _, _) = ask(
        &mut s,
        p,
        &Echo::request(1, 1, vec![Fec::Ldp("10.255.7.7/32".parse().unwrap())]),
        255,
    );
    assert_eq!(r.return_code, code::NO_MAPPING);
    // 10.77.0.2 is the responder's: egress.
    let mut rtts = Vec::new();
    for seq in 2..12 {
        let e = Echo::request(1, seq, vec![Fec::Ldp("10.77.0.2/32".parse().unwrap())]);
        let (r, from, rtt) = ask(&mut s, p, &e, 255);
        assert_eq!((r.return_code, r.return_subcode), (code::EGRESS, 1));
        assert_eq!(r.handle, 1);
        // The sent timestamp is stamped by the socket and copied back.
        assert_ne!(r.sent, (0, 0));
        assert!(from.is_ipv4());
        rtts.push(rtt);
    }
    rtts.sort();
    eprintln!(
        "LSP ping round trip over veth (median of 10): {:?}",
        rtts[5]
    );
    // Paths of a FEC without route: none.
    assert!(
        s.paths("192.0.2.77/32".parse().unwrap())
            .unwrap()
            .is_empty()
    );
    stop.store(true, Ordering::Relaxed);
    assert!(worker.join().unwrap() >= 11);
}

#[test]
fn a_label_ttl_that_expires_is_answered_by_the_transit_lsr() {
    let _one = ONE.lock().unwrap_or_else(|p| p.into_inner());
    if !in_netns() {
        return;
    }
    if !available() {
        assert!(
            std::env::var_os(REQUIRE).is_none_or(|v| v != "1"),
            "{REQUIRE}=1 but this kernel has no mpls_router"
        );
        eprintln!("skipped: no mpls_router (load it on the host: modprobe mpls_router)");
        return;
    }
    setup();
    std::fs::write("/proc/sys/net/mpls/platform_labels", "1000").unwrap();
    std::fs::write("/proc/sys/net/mpls/conf/lpb/input", "1").unwrap();
    ip(&[
        "route",
        "replace",
        "10.255.8.8/32",
        "encap",
        "mpls",
        "100",
        "via",
        "10.77.0.9",
        "dev",
        "lpa",
        "onlink",
    ]);
    ip(&[
        "-f",
        "mpls",
        "route",
        "replace",
        "100",
        "as",
        "200",
        "via",
        "inet",
        "10.77.0.9",
        "dev",
        "lpa",
    ]);
    let stop = Arc::new(AtomicBool::new(false));
    let worker = responder(stop.clone());
    let mut s = HostLspSocket::open().unwrap();
    let fec = "10.255.8.8/32".parse().unwrap();
    let paths = s.paths(fec).unwrap();
    assert_eq!(paths[0].labels, vec![100], "{paths:?}");
    let p = paths[0].clone();
    let mut e = Echo::request(2, 1, vec![Fec::Ldp(fec)]);
    // What R1 tells R2 to expect: label 100 on 10.77.0.2.
    e.ddmaps.push(ddmap_of(
        &MplsNexthop {
            via: Some("10.77.0.2".parse().unwrap()),
            interface: None,
            out_labels: vec![100],
        },
        Origin::Ldp,
        Some(1500),
        false,
    ));
    let (r, _, _) = ask(&mut s, &p, &e, 1);
    assert_eq!(
        (r.return_code, r.return_subcode),
        (code::LABEL_SWITCHED, 1),
        "{r:?}"
    );
    assert_eq!(r.ddmaps[0].labels[0].label, 200);
    // TTL 255 does not expire: the kernel switches it, nobody answers here.
    // A label without entry, with TTL 1: code 11.
    let mut bad = p.clone();
    bad.labels = vec![555];
    e.seq = 2;
    e.ddmaps.clear();
    let (r, _, _) = ask(&mut s, &bad, &e, 1);
    assert_eq!(r.return_code, code::NO_LABEL_ENTRY);
    stop.store(true, Ordering::Relaxed);
    worker.join().unwrap();
}

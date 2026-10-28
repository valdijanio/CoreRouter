//! G3.5b against real LDP labels, in the lab VM only
//! (`scripts/lsp-ping-live.sh` builds lsp1 — lsp2 — lsp3 with FRR's ldpd
//! over OSPF). Without `COREROUTER_LSP_LIVE=1` the test returns at once.
//!
//! CoreRouter's responder runs in lsp2 (transit, penultimate hop) and lsp3
//! (egress), each on a thread moved into its namespace (`setns`: sockets
//! belong to the namespace they are made in); the sender runs in lsp1.
//! What it shows, with the labels LDP handed out:
//! - ping 10.255.0.3/32: code 3 from the egress, every time;
//! - traceroute: hop 1 (lsp2) "label switched" with implicit null
//!   downstream (PHP), hop 2 (lsp3) egress;
//! - a label nobody bound, TTL 1: code 11 at lsp2.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::fs::File;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use corerouter_hal::lsp::respond::{Verdict, ddmap_of, respond};
use corerouter_hal::lsp::wire::{self, Echo, Fec, code};
use corerouter_hal::lsp::{LspPath, LspRequest, LspResponderIo, LspSocket, destination};
use corerouter_hal::mpls::MplsNexthop;
use corerouter_hal_linux::lsp::{HostLspSocket, HostResponder};
use nix::sched::{CloneFlags, setns};

fn enter(ns: &str) {
    let f = File::open(format!("/run/netns/{ns}")).unwrap();
    setns(f, CloneFlags::CLONE_NEWNET).unwrap();
}

fn responder(
    ns: &'static str,
    ifs: &'static [&'static str],
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<u64> {
    thread::Builder::new()
        .name(format!("lsp-{ns}"))
        .spawn(move || {
            enter(ns);
            let mut r = HostResponder::open().unwrap();
            let names: Vec<_> = ifs.iter().map(|i| i.parse().unwrap()).collect();
            assert!(r.set_interfaces(&names).is_empty());
            let mut n = 0;
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
                    n += 1;
                }
            }
            n
        })
        .unwrap()
}

fn ask(
    s: &mut HostLspSocket,
    path: &LspPath,
    e: &Echo,
    ttl: u8,
) -> Option<(Echo, IpAddr, Duration)> {
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
    while start.elapsed() < Duration::from_secs(2) {
        if let Some(a) = s.recv(Duration::from_millis(100)).unwrap() {
            let r = wire::parse(&a.payload).unwrap();
            if r.seq == e.seq {
                return Some((r, a.from, a.rtt.unwrap()));
            }
        }
    }
    None
}

#[test]
fn ping_and_trace_over_ldp() {
    if std::env::var("COREROUTER_LSP_LIVE").as_deref() != Ok("1") {
        eprintln!("skipped: COREROUTER_LSP_LIVE=1 (scripts/lsp-ping-live.sh, in the lab VM)");
        return;
    }
    let stop = Arc::new(AtomicBool::new(false));
    let r2 = responder("lsp2", &["l12b", "l23a"], stop.clone());
    let r3 = responder("lsp3", &["l23b"], stop.clone());
    thread::sleep(Duration::from_millis(300));
    let sender = thread::Builder::new()
        .name("lsp-sender".into())
        .spawn(|| {
            enter("lsp1");
            let mut s = HostLspSocket::open().unwrap();
            let fec = "10.255.0.3/32".parse().unwrap();
            let paths = s.paths(fec).unwrap();
            eprintln!("paths of {fec}: {paths:?}");
            let p = paths[0].clone();
            assert_eq!(p.labels.len(), 1, "LDP gave lsp1 a label for 10.255.0.3");
            // Ping: 200 requests, the round trips.
            let mut rtts = Vec::new();
            for seq in 1..=200 {
                let mut e = Echo::request(7, seq, vec![Fec::Ldp(fec)]);
                e.flags = wire::FLAG_VALIDATE;
                let (r, from, rtt) = ask(&mut s, &p, &e, 255).expect("egress reply");
                assert_eq!(
                    (r.return_code, r.return_subcode),
                    (code::EGRESS, 1),
                    "{r:?}"
                );
                assert!(from.to_string().starts_with("10."), "{from}");
                rtts.push(rtt);
            }
            rtts.sort();
            eprintln!(
                "LSP ping lsp1 → lsp3 (200 requests): min {:?} median {:?} p95 {:?} max {:?}",
                rtts[0], rtts[100], rtts[190], rtts[199]
            );
            // Traceroute.
            let mut e = Echo::request(8, 1000, vec![Fec::Ldp(fec)]);
            e.ddmaps.push(ddmap_of(
                &MplsNexthop {
                    via: p.nexthop,
                    interface: Some(p.interface.clone()),
                    out_labels: p.labels.clone(),
                },
                p.origin,
                p.mtu,
                false,
            ));
            let (h1, from1, _) = ask(&mut s, &p, &e, 1).expect("hop 1");
            eprintln!(
                "hop 1 {from1}: {} {:?}",
                wire::describe(h1.return_code, h1.return_subcode),
                h1.ddmaps
            );
            assert_eq!(h1.return_code, code::LABEL_SWITCHED);
            assert_eq!(
                h1.ddmaps[0].labels[0].label,
                wire::LABEL_IMPLICIT_NULL,
                "lsp2 pops (PHP)"
            );
            e.seq = 1001;
            e.ddmaps = vec![h1.ddmaps[0].clone()];
            let (h2, from2, _) = ask(&mut s, &p, &e, 2).expect("hop 2");
            eprintln!(
                "hop 2 {from2}: {}",
                wire::describe(h2.return_code, h2.return_subcode)
            );
            assert_eq!(h2.return_code, code::EGRESS);
            // A label lsp2 never bound.
            let mut bad = p.clone();
            bad.labels = vec![99_999];
            e.seq = 1002;
            e.ddmaps.clear();
            let (r, _, _) = ask(&mut s, &bad, &e, 1).expect("code 11");
            assert_eq!(r.return_code, code::NO_LABEL_ENTRY);
        })
        .unwrap();
    let result = sender.join();
    stop.store(true, Ordering::Relaxed);
    let (n2, n3) = (r2.join().unwrap(), r3.join().unwrap());
    eprintln!("replies: lsp2 {n2}, lsp3 {n3}");
    if let Err(p) = result {
        std::panic::resume_unwind(p);
    }
}

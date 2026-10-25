//! G4.3g: the PPPoE workers' sockets against a real kernel, inside a
//! throwaway network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test --release -p corerouter-hal-linux --test netns_pppoe_lanes -- --nocapture
//! ```
//!
//! PADIs from 200 000 MACs are written into one end of a veth. On the other
//! end, either one socket reads them all and hands each to a worker thread
//! by a channel (the service before G4.3g), or each worker reads its own
//! socket whose classic BPF filter keeps only its MACs (`open_lane`). The
//! second must deliver each frame to exactly one worker, the one `lane_of`
//! names, and the frames a second it delivers are printed for both.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use corerouter_hal_linux::pppoe_io::{PppoePort, lane_of};
use corerouter_model::IfName;

const ENV: &str = "COREROUTER_NETNS_TESTS";

fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!(
            "skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net` (cargo xtask netns)"
        );
        return false;
    }
    static FRESH: OnceLock<bool> = OnceLock::new();
    let fresh = *FRESH.get_or_init(|| {
        let out = Command::new("ip")
            .args(["-o", "link", "show"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&out.stdout).lines().count() == 1
    });
    assert!(
        fresh,
        "{ENV}=1 but this namespace has more than lo; refusing to touch it"
    );
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

fn name(n: &str) -> IfName {
    n.parse().unwrap()
}

/// A PADI from MAC number `i` (as the labs number them: a counter, then
/// a fixed last byte).
fn padi(i: u32) -> Vec<u8> {
    let mut f = vec![0xff; 6];
    f.extend_from_slice(&[0x02, 0x20, (i >> 16) as u8, (i >> 8) as u8, i as u8, 0x01]);
    f.extend_from_slice(&[
        0x88, 0x63, 0x11, 0x09, 0x00, 0x00, 0x00, 0x04, 0x01, 0x01, 0x00, 0x00,
    ]);
    f.resize(60, 0);
    f
}

/// Write `n` PADIs into `from`, a few at a time so the receivers are the
/// limit, not the socket buffers.
fn blast(from: &PppoePort, n: u32, got: &AtomicU64) -> Duration {
    let t = Instant::now();
    for i in 0..n {
        while u64::from(i) > got.load(Ordering::Relaxed) + 2000 {
            std::hint::spin_loop();
            if t.elapsed() > Duration::from_secs(60) {
                break;
            }
        }
        let _ = from.send(&padi(i));
    }
    t.elapsed()
}

/// CPU seconds (user + system) of the calling thread.
fn thread_cpu() -> f64 {
    let stat = std::fs::read_to_string("/proc/thread-self/stat").unwrap_or_default();
    let rest = stat.rsplit_once(')').map_or("", |(_, r)| r);
    let f: Vec<&str> = rest.split_whitespace().collect();
    let ticks: f64 = f.get(11).and_then(|v| v.parse().ok()).unwrap_or(0.0)
        + f.get(12).and_then(|v| v.parse().ok()).unwrap_or(0.0);
    ticks / 100.0
}

/// Sleep until the port has a frame (or 10 ms), as the service's threads do.
fn wait(port: &PppoePort) {
    use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
    let mut fds: Vec<PollFd<'_>> = port
        .fds()
        .into_iter()
        .map(|f| PollFd::new(f, PollFlags::POLLIN))
        .collect();
    let _ = poll(&mut fds, PollTimeout::from(10u8));
}

fn wait_for(got: &AtomicU64, n: u64) -> Duration {
    let t = Instant::now();
    while got.load(Ordering::Relaxed) < n && t.elapsed() < Duration::from_secs(60) {
        std::thread::sleep(Duration::from_millis(1));
    }
    t.elapsed()
}

#[test]
fn each_worker_reads_its_own_clients() {
    if !in_netns() {
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    ip(&["link", "add", "lna", "type", "veth", "peer", "name", "lnb"]);
    ip(&["link", "set", "lna", "up"]);
    ip(&["link", "set", "lnb", "up"]);
    let n: u32 = 200_000;
    let sender = PppoePort::open(&name("lnb"), &[], true).unwrap();
    let mut line = String::new();
    for lanes in [1u16, 2, 4, 6] {
        // Before: one reader hands every frame to its worker by a channel.
        let got = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let mut port = PppoePort::open(&name("lna"), &[], true).unwrap();
        let mut txs = Vec::new();
        let mut workers = Vec::new();
        for _ in 0..lanes {
            let (tx, rx) = sync_channel::<Vec<u8>>(1 << 16);
            txs.push(tx);
            let got = got.clone();
            workers.push(std::thread::spawn(move || {
                let c0 = thread_cpu();
                while let Ok(f) = rx.recv() {
                    std::hint::black_box(&f);
                    got.fetch_add(1, Ordering::Relaxed);
                }
                thread_cpu() - c0
            }));
        }
        let reader = {
            let stop = stop.clone();
            std::thread::spawn(move || {
                let c0 = thread_cpu();
                while !stop.load(Ordering::Relaxed) {
                    port.recv(|f| {
                        let _ = txs[usize::from(lane_of(f, lanes))].send(f.to_vec());
                    })
                    .unwrap();
                    wait(&port);
                }
                thread_cpu() - c0
            })
        };
        let sent = blast(&sender, n, &got);
        let drained = wait_for(&got, u64::from(n));
        stop.store(true, Ordering::Relaxed);
        let reader_cpu = reader.join().unwrap();
        for w in workers {
            w.join().unwrap();
        }
        let _ = (sent, drained);
        assert_eq!(
            got.load(Ordering::Relaxed),
            u64::from(n),
            "the reader lost frames"
        );

        // After: each worker its own filtered socket.
        let got = Arc::new(AtomicU64::new(0));
        let wrong = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::new();
        for lane in 0..lanes {
            let mut port = PppoePort::open_lane(&name("lna"), &[], true, lane, lanes).unwrap();
            let (got, wrong, stop) = (got.clone(), wrong.clone(), stop.clone());
            workers.push(std::thread::spawn(move || {
                let c0 = thread_cpu();
                while !stop.load(Ordering::Relaxed) {
                    port.recv(|f| {
                        if lane_of(f, lanes) != lane {
                            wrong.fetch_add(1, Ordering::Relaxed);
                        }
                        std::hint::black_box(f);
                        got.fetch_add(1, Ordering::Relaxed);
                    })
                    .unwrap();
                    wait(&port);
                }
                thread_cpu() - c0
            }));
        }
        let sent = blast(&sender, n, &got);
        let drained = wait_for(&got, u64::from(n));
        // Late copies, if a filter let a frame into two sockets.
        std::thread::sleep(Duration::from_millis(100));
        stop.store(true, Ordering::Relaxed);
        let busiest = workers
            .into_iter()
            .map(|w| w.join().unwrap())
            .fold(0.0, f64::max);
        let _ = (sent, drained);
        assert_eq!(
            got.load(Ordering::Relaxed),
            u64::from(n),
            "each frame to exactly one worker"
        );
        assert_eq!(wrong.load(Ordering::Relaxed), 0, "and to the right one");
        // The serial part: what one thread spends per frame bounds the rate
        // (the reader for every frame; with own sockets, the busiest worker
        // for its share).
        let ns = |cpu: f64| cpu * 1e9 / f64::from(n);
        line.push_str(&format!(
            " {lanes}: reader {:.0} ns/frame (≤ {:.1} M/s), busiest own socket {:.0} ns/frame (≤ {:.1} M/s);",
            ns(reader_cpu),
            1e3 / ns(reader_cpu).max(1.0),
            ns(busiest),
            1e3 / ns(busiest).max(1.0)
        ));
    }
    println!(
        "MEASURED pppoe lanes: {n} PADIs over a veth, CPU of the busiest receiving thread:{line}"
    );
}

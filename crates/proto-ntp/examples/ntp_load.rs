//! Load generator for an NTP server (G4.6c): closed loop, like many clients
//! with a window of requests in flight; prints replies per second and latency.
//! Each thread sends from its own loopback address (127.1.x.y), so a server's
//! per-source rate limit sees many sources, as in a real LAN.
//!
//! ```sh
//! cargo run --release -p corerouter-proto-ntp --example ntp_load -- \
//!     127.0.0.1:123 <threads> <seconds> [window] [sources]
//! ```
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use corerouter_proto_ntp::{MODE_SERVER, Packet, Timestamp};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let target: SocketAddr = args[1].parse().unwrap();
    let threads: usize = args[2].parse().unwrap();
    let secs: u64 = args[3].parse().unwrap();
    let window: usize = args.get(4).map_or(16, |v| v.parse().unwrap());
    // Sockets per thread: every source address is one client to the server.
    let sources: usize = args.get(5).map_or(256, |v| v.parse().unwrap());
    let done = Arc::new(AtomicU64::new(0));
    let lost = Arc::new(AtomicU64::new(0));
    let kisses = Arc::new(AtomicU64::new(0));
    let mut handles = Vec::new();
    for t in 0..threads {
        let (done, lost, kisses) = (done.clone(), lost.clone(), kisses.clone());
        handles.push(
            std::thread::Builder::new()
                .name(format!("load-{t}"))
                .spawn(move || {
                    let socks: Vec<UdpSocket> = (0..sources)
                        .map(|i| {
                            let ip = [127, 1 + t as u8, (i >> 8) as u8, (i & 0xff) as u8 + 1];
                            let s = UdpSocket::bind(SocketAddr::from((ip, 0))).unwrap();
                            s.connect(target).unwrap();
                            s.set_nonblocking(true).unwrap();
                            s
                        })
                        .collect();
                    let mut buf = [0u8; 128];
                    let mut lat: Vec<u32> = Vec::with_capacity(1 << 20);
                    let mut next = 0usize;
                    let mut in_flight = vec![None::<Instant>; sources];
                    let mut out = 0usize;
                    let end = Instant::now() + Duration::from_secs(secs);
                    let mut stamp = 1u64;
                    while Instant::now() < end {
                        while out < window {
                            let i = next % sources;
                            next += 1;
                            if in_flight[i].is_some() {
                                continue;
                            }
                            stamp += 1;
                            let p = Packet::client_request(Timestamp(stamp << 8));
                            if socks[i].send(&p.encode()).is_ok() {
                                in_flight[i] = Some(Instant::now());
                                out += 1;
                            }
                        }
                        let mut got = false;
                        for (i, s) in socks.iter().enumerate() {
                            let Some(sent) = in_flight[i] else { continue };
                            match s.recv(&mut buf) {
                                Ok(n) => {
                                    got = true;
                                    in_flight[i] = None;
                                    out -= 1;
                                    let r = Packet::decode(&buf[..n]).unwrap();
                                    assert_eq!(r.mode, MODE_SERVER);
                                    if r.stratum == 0 {
                                        kisses.fetch_add(1, Ordering::Relaxed);
                                    } else {
                                        done.fetch_add(1, Ordering::Relaxed);
                                        if lat.len() < lat.capacity() {
                                            lat.push(sent.elapsed().as_nanos() as u32);
                                        }
                                    }
                                }
                                Err(_) => {
                                    if sent.elapsed() > Duration::from_millis(500) {
                                        in_flight[i] = None;
                                        out -= 1;
                                        lost.fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                        }
                        if !got {
                            std::hint::spin_loop();
                        }
                    }
                    lat
                })
                .unwrap(),
        );
    }
    let mut all: Vec<u32> = Vec::new();
    for h in handles {
        all.extend(h.join().unwrap());
    }
    all.sort_unstable();
    let pct = |p: f64| {
        all.get(((all.len() as f64 * p) as usize).min(all.len().saturating_sub(1)))
            .copied()
            .unwrap_or(0) as f64
            / 1e3
    };
    println!(
        "replies/s {:.0}  kisses {}  lost {}  p50 {:.0} µs  p99 {:.0} µs",
        done.load(Ordering::Relaxed) as f64 / secs as f64,
        kisses.load(Ordering::Relaxed),
        lost.load(Ordering::Relaxed),
        pct(0.50),
        pct(0.99)
    );
}

//! G4.2a — a storm of N clients through the pure DHCP server: leases/s and
//! the p50/p99/max time to handle one message (`Instant` around each
//! `Server::handle`). `cargo run --release -p corerouter-proto-dhcp
//! --example storm [N]` (default 10000).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

mod lab;

use std::time::Instant;

fn main() {
    let n: usize = std::env::args()
        .nth(1)
        .and_then(|a| a.parse().ok())
        .unwrap_or(10_000);
    for probed in [false, true] {
        let lab = lab::Storm::new(n, probed);
        let mut srv = lab.server();
        let mut times: Vec<u128> = Vec::with_capacity(2 * n);
        let start = Instant::now();
        let acks = lab.run(&mut srv, |f| {
            let t = Instant::now();
            f();
            times.push(t.elapsed().as_nanos());
        });
        let total = start.elapsed();
        times.sort_unstable();
        let q = |p: f64| {
            let i = ((times.len() as f64 * p) as usize).min(times.len().saturating_sub(1));
            times.get(i).copied().unwrap_or(0) as f64 / 1000.0
        };
        println!(
            "{} n={n}: {acks} ACKs in {:.1} ms = {:.0} leases/s; per message p50 {:.1} µs, p99 {:.1} µs, max {:.1} µs",
            if probed { "probed" } else { "dora  " },
            total.as_secs_f64() * 1000.0,
            acks as f64 / total.as_secs_f64(),
            q(0.5),
            q(0.99),
            q(1.0),
        );
    }
}

//! The numbers of `docs/netsim.md` (`## Desempenho`):
//!
//! ```sh
//! cargo run --release -p corerouter-netsim --example measure -- 10 100 500
//! ```
//!
//! For each size: a grid with OSPF on every link and eBGP between every
//! pair of neighbors (each router its own AS, one /24 each), built and run
//! for 60 virtual seconds from power-on (convergence), then 10 virtual
//! minutes of steady state, then 30 s after a link cut, on 1 thread and on
//! more.

use std::time::Instant;

use corerouter_netsim::preset::{self, BgpMode};
use corerouter_netsim::{Fault, LinkId, SEC};

fn main() {
    let sizes: Vec<usize> = std::env::args()
        .skip(1)
        .filter_map(|a| a.parse().ok())
        .collect();
    let sizes = if sizes.is_empty() {
        vec![10, 100]
    } else {
        sizes
    };
    let cores = std::thread::available_parallelism().map_or(1, |c| c.get());
    println!("{cores} CPUs");
    for n in sizes {
        for threads in [1usize, 4, 8, cores.min(16)] {
            let t = Instant::now();
            let mut sim = match preset::grid(n, BgpMode::Ebgp).build(1) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("{e}");
                    return;
                }
            };
            let built = t.elapsed();
            sim.set_threads(threads);
            let t = Instant::now();
            sim.advance(60 * SEC, u64::MAX);
            let conv = t.elapsed();
            let st = sim.stats();
            let last = sim.last_change().unwrap_or(0);
            let t = Instant::now();
            sim.advance(660 * SEC, u64::MAX);
            let steady = t.elapsed();
            let st2 = sim.stats();
            let now = sim.now();
            let cut = LinkId(u32::try_from(sim.link_count() / 2).unwrap_or(0));
            let _ = sim.schedule(now, Fault::LinkCut { link: cut });
            let t = Instant::now();
            sim.advance(now + 30 * SEC, u64::MAX);
            let fail = t.elapsed();
            println!(
                "n={n:4} links={:4} threads={threads:2} build={:6.1} ms | converge 60 s: {:8.1} ms, \
                 {} windows ({} parallel), {} events, {:.1} µs/window, barrier {:.0} ms, last change at {:.2} s | \
                 steady 600 s: {:7.1} ms ({} events) | cut + 30 s: {:6.1} ms | state ≈ {} B/router",
                sim.link_count(),
                built.as_secs_f64() * 1e3,
                conv.as_secs_f64() * 1e3,
                st.windows,
                st.parallel_windows,
                st.events,
                conv.as_secs_f64() * 1e6 / st.windows.max(1) as f64,
                st.barrier_ns as f64 / 1e6,
                last as f64 / 1e6,
                steady.as_secs_f64() * 1e3,
                st2.events - st.events,
                fail.as_secs_f64() * 1e3,
                sim.approx_bytes() / n.max(1),
            );
        }
    }
}

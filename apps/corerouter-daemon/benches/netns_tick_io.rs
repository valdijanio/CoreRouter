//! G1.3i — the kernel reads of the clock's tick besides the link poll, and
//! how long the tick holds the session lock with them, inside a throwaway
//! network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- \
//!     cargo bench -p corerouter-daemon --bench netns_tick_io
//! ```
//!
//! Eight managed dummy ports (`tp0..tp7`, `--manage tp*`), System ›
//! Graphing on with the machine's resources. In steps up to each size of
//! `COREROUTER_TICK_IO_SIZES` (default `1000,10000,100000`), IPv6 routes of
//! another protocol (`proto bgp`, what FRR installs) on the ports, plus a
//! few hundred learned ones on ports that accept Router Advertisements
//! (an address with a lifetime, `proto ra` routes); `COREROUTER_TICK_IO_RA=0` leaves RA off (the usual
//! router: no learned state, no walk of the table for it). Per size:
//! - `learned`: `Hal::ipv6_learned` alone (a dump of the v6 addresses and
//!   of the whole v6 route table);
//! - `resources`: `Hal::resources` alone (the graphs' CPU and memory);
//! - `read`: the clock's read with the session unlocked (the links, G1.3f,
//!   and since G1.3i the IPv6 state);
//! - `tick`: how long the clock's tick then holds the session lock;
//! - `wait`: a cheap command every 2 ms for 5 s while a second thread ticks
//!   once a second (median, p99, max).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("skipped: netlink is Linux-only");
}

#[cfg(target_os = "linux")]
fn main() {
    if !linux::ready() {
        return;
    }
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use corerouter_engine::{Caller, Session, Shared, lock, shared};
    use corerouter_hal::Hal;
    use corerouter_hal_linux::{LinuxHal, Policy};
    use serde_json::json;

    const ENV: &str = "COREROUTER_NETNS_BENCH";
    const ROUNDS: usize = 20;
    const PORTS: usize = 8;
    /// Learned (RA) routes and SLAAC-like addresses, per port.
    const LEARNED: usize = 32;

    pub fn ready() -> bool {
        if std::env::var_os(ENV).is_none_or(|v| v != "1") {
            eprintln!(
                "skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net` \
                 (cargo xtask bench)"
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
            .collect();
        assert_eq!(
            names,
            ["lo"],
            "{ENV}=1 but this namespace is not fresh; refusing to touch it"
        );
        true
    }

    fn ip_batch(script: &str) {
        let mut child = Command::new("ip")
            .args(["-batch", "-"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success());
    }

    fn ports() {
        let mut s = String::from("link set lo up\n");
        for p in 0..PORTS {
            s.push_str(&format!("link add tp{p} up type dummy\n"));
        }
        ip_batch(&s);
    }

    /// What the kernel would have learned from Router Advertisements: an
    /// address with a lifetime and a `proto ra` route, [`LEARNED`] of each
    /// per port (added once the ports accept RA: the first apply flushes
    /// what a port learned while CoreRouter did not let it).
    fn learned() {
        let mut s = String::new();
        for p in 0..PORTS {
            for i in 0..LEARNED {
                s.push_str(&format!(
                    "addr add 2001:db8:{p}:{i:x}::1/64 dev tp{p} valid_lft 3600 preferred_lft 1800\n"
                ));
                s.push_str(&format!(
                    "route add 2001:db8:a{p}:{i:x}::/64 dev tp{p} proto ra expires 1800\n"
                ));
            }
        }
        ip_batch(&s);
    }

    /// `proto bgp` routes `from..to` spread over the ports.
    fn bgp_routes(from: usize, to: usize) {
        let mut s = String::new();
        for i in from..to {
            let (hi, lo) = (i >> 16, i & 0xffff);
            s.push_str(&format!(
                "route add 2001:db8:{:x}:{lo:x}::/64 dev tp{} proto bgp\n",
                0x1000 + hi,
                i % PORTS
            ));
        }
        ip_batch(&s);
    }

    /// One tick as the clock thread does it: (read unlocked, lock held).
    fn clock_tick(session: &Shared, now: u64) -> (Duration, Duration) {
        let t = Instant::now();
        let reader = lock(session).link_reader();
        let links = reader.map(|mut r| r.read());
        let read = t.elapsed();
        let t = Instant::now();
        lock(session).tick_sampled(now, links);
        (read, t.elapsed())
    }

    fn pct(v: &mut [Duration], p: f64) -> Duration {
        v.sort();
        let i = ((v.len() as f64 - 1.0) * p).round() as usize;
        v[i.min(v.len() - 1)]
    }

    fn timed<T>(n: usize, mut f: impl FnMut() -> T) -> Vec<Duration> {
        (0..n)
            .map(|_| {
                let t = Instant::now();
                std::hint::black_box(f());
                t.elapsed()
            })
            .collect()
    }

    pub fn run() {
        let sizes: Vec<usize> = std::env::var("COREROUTER_TICK_IO_SIZES")
            .ok()
            .map(|v| v.split(',').filter_map(|s| s.trim().parse().ok()).collect())
            .unwrap_or_else(|| vec![1000, 10_000, 100_000]);
        ports();
        let policy = || Policy {
            manage: vec!["tp*".into()],
            unmanaged: Vec::new(),
        };
        let session = shared(Session::new(Box::new(LinuxHal::with_policy(policy()))));
        lock(&session)
            .execute(
                "system.graph.set",
                &json!({"enabled": true, "resources": true}),
            )
            .unwrap();
        let ra = std::env::var("COREROUTER_TICK_IO_RA").as_deref() != Ok("0");
        if ra {
            lock(&session)
                .execute(
                    "ipv6.settings.set",
                    &json!({"accept_router_advertisements": "yes", "accept_router_advertisements_on": "all"}),
                )
                .unwrap();
            learned();
        }
        // The tick's first look adopts the ports.
        clock_tick(&session, 1_900_000_000);
        let mut bare = LinuxHal::with_policy(policy());
        bare.poll();
        let learned = bare.ipv6_learned().unwrap().len();
        let ra = lock(&session)
            .execute("ip.route.list", &json!({"origin": "ra"}))
            .unwrap();
        let ra = ra.as_array().map_or(0, Vec::len);
        println!("learned entries on the ports: {learned} (hal), {ra} ra routes listed");
        println!(
            "| v6 routes (bgp) | ipv6_learned (median / max) | resources (median) | read unlocked (median) | \
             tick under lock (median / max) | command wait while ticking (median / p99 / max) |"
        );
        println!("|---|---|---|---|---|---|");
        let mut have = 0;
        for n in sizes {
            if n > have {
                bgp_routes(have, n);
                have = n;
            }
            let mut learned = timed(ROUNDS, || {
                bare.poll();
                bare.ipv6_learned().unwrap()
            });
            let mut res = timed(ROUNDS, || bare.resources());
            let (mut reads, mut ticks): (Vec<Duration>, Vec<Duration>) = (0..ROUNDS)
                .map(|i| {
                    // A second apart, as the clock reads (the IPv6 state is
                    // read again once the last read is ~1 s old).
                    std::thread::sleep(Duration::from_millis(950));
                    clock_tick(&session, 1_900_000_100 + i as u64)
                })
                .unzip();
            let stop = AtomicBool::new(false);
            let mut waits = Vec::new();
            std::thread::scope(|sc| {
                sc.spawn(|| {
                    let mut i = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        let _ = clock_tick(&session, 1_950_000_000 + i);
                        i += 1;
                        std::thread::sleep(Duration::from_secs(1));
                    }
                });
                let until = Instant::now() + Duration::from_secs(5);
                while Instant::now() < until {
                    let t = Instant::now();
                    lock(&session)
                        .execute_as(&Caller::local(), "system.identity.get", &json!({}))
                        .unwrap();
                    waits.push(t.elapsed());
                    std::thread::sleep(Duration::from_millis(2));
                }
                stop.store(true, Ordering::Relaxed);
            });
            println!(
                "| {n} | {:.2?} / {:.2?} | {:.2?} | {:.2?} | {:.2?} / {:.2?} | {:.2?} / {:.2?} / {:.2?} ({} calls) |",
                pct(&mut learned, 0.5),
                pct(&mut learned, 1.0),
                pct(&mut res, 0.5),
                pct(&mut reads, 0.5),
                pct(&mut ticks, 0.5),
                pct(&mut ticks, 1.0),
                pct(&mut waits, 0.5),
                pct(&mut waits, 0.99),
                pct(&mut waits, 1.0),
                waits.len(),
            );
        }
    }
}

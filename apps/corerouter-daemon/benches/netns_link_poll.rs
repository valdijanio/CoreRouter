//! G1.3f — how long the clock's link poll holds the session lock with many
//! kernel links, and how long a command waits behind it, inside a throwaway
//! network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- \
//!     cargo bench -p corerouter-daemon --bench netns_link_poll
//! ```
//!
//! `COREROUTER_LINK_POLL_SIZES` (default `100,1000,10000`) dummy links are
//! added in steps (a BNG has one `ppp` link per subscriber). Per size:
//! - `hal.poll`: `LinuxHal::poll` alone (dump + counters), no session;
//! - `tick`: `Session::tick` of a `--backend linux` session, all of it
//!   under the session lock (what the clock thread holds);
//! - `wait`: a cheap command (`system.identity.get`) sent from another
//!   thread every 2 ms for 5 s while a second thread ticks once a second,
//!   as the clock does: how long it waits for the lock and runs (median,
//!   p99, max; the max is a command that came at the start of a tick).

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

    use corerouter_engine::{Caller, Session, lock, shared};
    use corerouter_hal::Hal;
    use corerouter_hal_linux::LinuxHal;
    use serde_json::json;

    const ENV: &str = "COREROUTER_NETNS_BENCH";
    const ROUNDS: usize = 30;

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

    /// Dummy links `bd<from>..bd<to>`, up, in one `ip -batch`.
    fn add_dummies(from: usize, to: usize) {
        let mut child = Command::new("ip")
            .args(["-batch", "-"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        let mut script = String::new();
        for i in from..to {
            script.push_str(&format!("link add bd{i} up type dummy\n"));
        }
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success());
    }

    fn pct(v: &mut [Duration], p: f64) -> Duration {
        v.sort();
        let i = ((v.len() as f64 - 1.0) * p).round() as usize;
        v[i.min(v.len() - 1)]
    }

    pub fn run() {
        let sizes: Vec<usize> = std::env::var("COREROUTER_LINK_POLL_SIZES")
            .ok()
            .map(|v| v.split(',').filter_map(|s| s.trim().parse().ok()).collect())
            .unwrap_or_else(|| vec![100, 1000, 10_000]);
        let mut bare = LinuxHal::new();
        let session = shared(Session::new(Box::new(LinuxHal::new())));
        let mut have = 0;
        println!(
            "| links | hal.poll (median / max) | tick under lock (median / max) | \
             command wait while ticking (median / p99 / max) | idle command |"
        );
        println!("|---|---|---|---|---|");
        for n in sizes {
            if n > have {
                add_dummies(have, n);
                have = n;
            }
            let mut polls: Vec<Duration> = (0..ROUNDS)
                .map(|_| {
                    let t = Instant::now();
                    std::hint::black_box(bare.poll());
                    t.elapsed()
                })
                .collect();
            let mut ticks: Vec<Duration> = (0..ROUNDS)
                .map(|i| {
                    let t = Instant::now();
                    lock(&session).tick(1_900_000_000 + i as u64);
                    t.elapsed()
                })
                .collect();
            let cmd = |s: &mut Session| {
                s.execute_as(&Caller::local(), "system.identity.get", &json!({}))
                    .unwrap();
            };
            let mut idle: Vec<Duration> = (0..ROUNDS)
                .map(|_| {
                    let t = Instant::now();
                    cmd(&mut lock(&session));
                    t.elapsed()
                })
                .collect();
            let stop = AtomicBool::new(false);
            let mut waits = Vec::new();
            std::thread::scope(|sc| {
                sc.spawn(|| {
                    let mut i = 0u64;
                    while !stop.load(Ordering::Relaxed) {
                        lock(&session).tick(1_950_000_000 + i);
                        i += 1;
                        // Once a second, as the clock thread does.
                        std::thread::sleep(Duration::from_secs(1));
                    }
                });
                let until = Instant::now() + Duration::from_secs(5);
                while Instant::now() < until {
                    let t = Instant::now();
                    cmd(&mut lock(&session));
                    waits.push(t.elapsed());
                    std::thread::sleep(Duration::from_millis(2));
                }
                stop.store(true, Ordering::Relaxed);
            });
            let (pm, px) = (pct(&mut polls, 0.5), pct(&mut polls, 1.0));
            let (tm, tx) = (pct(&mut ticks, 0.5), pct(&mut ticks, 1.0));
            println!(
                "| {n} | {pm:.2?} / {px:.2?} | {tm:.2?} / {tx:.2?} | {:.2?} / {:.2?} / {:.2?} ({} calls) | {:.2?} |",
                pct(&mut waits, 0.5),
                pct(&mut waits, 0.99),
                pct(&mut waits, 1.0),
                waits.len(),
                pct(&mut idle, 0.5),
            );
        }
    }
}

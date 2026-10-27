//! G1.27d — reading a neighbor table of 100 000 entries from the kernel:
//! our `RTM_GETNEIGH` dump (`LinuxHal::neighbors`, what the daemon does at
//! start and after a lost event) against `ip -j neigh show` and parsing
//! its JSON (the obvious alternative), and how fast the event feed takes
//! a burst of changes, inside a throwaway network namespace (no root):
//!
//! ```sh
//! COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- \
//!     cargo bench -p corerouter-hal-linux --bench netns_neigh
//! ```

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
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
    use std::process::Command;
    const ENV: &str = "COREROUTER_NETNS_BENCH";
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!(
            "skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net` (cargo xtask bench)"
        );
        return;
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
    let mut c = criterion::Criterion::default().configure_from_args();
    linux::dump(&mut c);
    c.final_summary();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::io::Write as _;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use corerouter_hal::Hal;
    use corerouter_hal::neigh::NeighborFeed;
    use corerouter_hal_linux::LinuxHal;
    use criterion::{Criterion, Throughput};

    const N: u32 = 100_000;

    fn batch(lines: &str) {
        let mut child = Command::new("ip")
            .args(["-batch", "-"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(lines.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success());
    }

    fn ip(args: &[&str]) {
        assert!(Command::new("ip").args(args).status().unwrap().success());
    }

    fn entries(from: u32, to: u32, mac_byte: u8) -> String {
        let mut lines = String::new();
        for i in from..to {
            lines.push_str(&format!(
                "neigh replace 100.{}.{}.{} lladdr 02:{mac_byte:02x}:00:{:02x}:{:02x}:{:02x} dev nbz0 nud permanent\n",
                64 + (i >> 16),
                (i >> 8) & 0xff,
                i & 0xff,
                (i >> 16) & 0xff,
                (i >> 8) & 0xff,
                i & 0xff
            ));
        }
        lines
    }

    pub fn dump(c: &mut Criterion) {
        ip(&[
            "link", "add", "nbz0", "type", "veth", "peer", "name", "nbz1",
        ]);
        ip(&["addr", "add", "100.64.0.1/10", "dev", "nbz0"]);
        ip(&["link", "set", "nbz0", "up"]);
        ip(&["link", "set", "nbz1", "up"]);
        let t = Instant::now();
        batch(&entries(0, N, 0));
        eprintln!(
            "netns_neigh: {N} entries made by `ip -batch` in {:?}",
            t.elapsed()
        );

        let mut hal = LinuxHal::new();
        assert!(hal.neighbors().unwrap().len() >= N as usize);
        let mut g = c.benchmark_group("netns_neigh_100k");
        g.sample_size(10);
        g.measurement_time(Duration::from_secs(10));
        g.throughput(Throughput::Elements(u64::from(N)));
        g.bench_function("rtm_getneigh_dump", |b| b.iter(|| hal.neighbors().unwrap()));
        g.bench_function("ip_json_parse", |b| {
            b.iter(|| {
                let out = Command::new("ip")
                    .args(["-j", "neigh", "show"])
                    .output()
                    .unwrap();
                let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
                v.as_array().unwrap().len()
            })
        });
        g.finish();

        // A burst: every entry changes its MAC; how fast the feed takes
        // all the events (the daemon's thread does the same, plus O(1)
        // per event in the table).
        let mut feed = hal.neighbor_feed().unwrap();
        let mut first = Vec::new();
        feed.dump(&mut first).unwrap();
        let mut ev = Vec::new();
        let lines = entries(0, 20_000, 1);
        let t = Instant::now();
        batch(&lines);
        let made = t.elapsed();
        let mut got = 0usize;
        let t = Instant::now();
        while got < 20_000 && t.elapsed() < Duration::from_secs(10) {
            ev.clear();
            feed.recv(200, 4096, &mut ev).unwrap();
            got += ev.len();
        }
        eprintln!(
            "netns_neigh: burst of 20000 changes made in {made:?}; feed read {got} events \
             {:?} after the burst ended, {} lost",
            t.elapsed(),
            feed.lost()
        );
        ip(&["link", "del", "nbz0"]);
    }
}

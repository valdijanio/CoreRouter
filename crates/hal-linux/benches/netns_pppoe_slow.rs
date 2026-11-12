//! G4.3y — the PPPoE slow path per packet: a subscriber's ICMP echo to the
//! gateway (the profile's `local_address` on `bng0`) written in
//! (`SlowPath::inject`) and its reply read back (`SlowPath::recv`), round
//! trip, inside a throwaway network namespace (no root):
//!
//! ```sh
//! COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- \
//!     cargo bench -p corerouter-hal-linux --bench netns_pppoe_slow
//! ```
//!
//! The same file measures the path before G4.3y (raw socket, in by `lo`)
//! and after (written into `bng0p`, received on `bng0`): the API is the
//! same.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("skipped: the slow path is Linux-only");
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
    let out = Command::new("ip").args(["-o", "link", "show"]).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let names: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split(':').nth(1))
        .map(|n| n.trim().split('@').next().unwrap_or(""))
        .collect();
    assert!(
        names.iter().all(|n| ["lo", "bng0", "bng0p", "bng0br"].contains(n)),
        "{ENV}=1 but this namespace is not fresh ({names:?}); refusing to touch it"
    );
    let _ = Command::new("ip").args(["link", "set", "lo", "up"]).status();
    let mut c = criterion::Criterion::default().configure_from_args();
    linux::echo(&mut c);
    c.final_summary();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    use corerouter_hal_linux::pppoe_io::{SlowPath, set_local_addresses};

    const SUB: Ipv4Addr = Ipv4Addr::new(100, 64, 0, 2);
    const GW: Ipv4Addr = Ipv4Addr::new(100, 65, 0, 1);

    fn csum(b: &[u8]) -> u16 {
        let mut s: u32 = 0;
        for ch in b.chunks(2) {
            s += u32::from(u16::from_be_bytes([ch[0], *ch.get(1).unwrap_or(&0)]));
        }
        while s > 0xffff {
            s = (s & 0xffff) + (s >> 16);
        }
        !(s as u16)
    }

    /// An ICMP echo request of `len` bytes in all, sequence `seq`.
    fn echo_packet(seq: u16, len: usize) -> Vec<u8> {
        let mut icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0, 0];
        icmp[6..8].copy_from_slice(&seq.to_be_bytes());
        icmp.resize(len - 20, 0xab);
        let c = csum(&icmp);
        icmp[2..4].copy_from_slice(&c.to_be_bytes());
        let mut ip = vec![0x45, 0, 0, 0, 0, 1, 0, 0, 64, 1, 0, 0];
        ip[2..4].copy_from_slice(&(len as u16).to_be_bytes());
        ip.extend_from_slice(&SUB.octets());
        ip.extend_from_slice(&GW.octets());
        let c = csum(&ip);
        ip[10..12].copy_from_slice(&c.to_be_bytes());
        ip.extend_from_slice(&icmp);
        ip
    }

    pub fn echo_round_trip(slow: &mut SlowPath, pkt: &[u8]) {
        slow.inject(pkt).unwrap();
        let start = Instant::now();
        loop {
            let mut got = false;
            slow.recv(|ip| got |= ip.len() > 20 && ip[9] == 1 && ip[20] == 0)
                .unwrap();
            if got {
                return;
            }
            assert!(start.elapsed() < Duration::from_secs(2), "no echo reply");
        }
    }

    pub fn echo(c: &mut criterion::Criterion) {
        let mut slow = SlowPath::open().unwrap();
        set_local_addresses(&[GW].into_iter().collect()).unwrap();
        slow.add_route(SUB).unwrap();
        let mut g = c.benchmark_group("pppoe_slow");
        for len in [64usize, 1400] {
            let pkt = echo_packet(1, len);
            echo_round_trip(&mut slow, &pkt);
            g.throughput(criterion::Throughput::Elements(1));
            g.bench_function(format!("echo_round_trip/{len}B"), |b| {
                b.iter(|| echo_round_trip(&mut slow, &pkt));
            });
        }
        g.finish();
    }
}

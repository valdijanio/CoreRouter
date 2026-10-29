//! G3.9d — what the responder's taps cost the MPLS data path: labeled
//! frames switched per second by the kernel, without and with the packet
//! sockets (classic BPF filter: top TTL ≤ 1 or explicit null) the
//! `lsp-ping` service keeps on every MPLS interface, inside a throwaway
//! network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- \
//!     cargo bench -p corerouter-hal-linux --bench netns_mpls_ttl
//! ```
//!
//! 64-byte frames with label 100 (TTL 64) are written with `AF_PACKET`
//! into veth `ta`; they come in on its peer `tb` (MPLS input on), are
//! swapped to 200 and leave by dummy `to`, whose `tx_packets` count them.
//! Needs `mpls_router` (the lab VM: `cargo xtask vm-lab run`); without it,
//! skips.

// A benchmark is test code: fixtures may unwrap (clippy.toml only covers #[test]).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("skipped: AF_PACKET and netlink are Linux-only");
}

#[cfg(target_os = "linux")]
fn main() {
    if !linux::ready() {
        return;
    }
    let mut c = criterion::Criterion::default().configure_from_args();
    linux::switch(&mut c);
    c.final_summary();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::AsRawFd;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use corerouter_hal::Hal;
    use corerouter_hal::lsp::LspResponderIo;
    use corerouter_hal_linux::lsp::HostResponder;
    use corerouter_hal_linux::{LinuxHal, Policy};
    use criterion::{Criterion, Throughput};
    use nix::ifaddrs::getifaddrs;
    use nix::sys::socket::{LinkAddr, MsgFlags, bind, send};
    use socket2::{Domain, Protocol, Socket, Type};

    const ENV: &str = "COREROUTER_NETNS_BENCH";
    /// Frames per iteration.
    const BURST: u64 = 20_000;

    pub fn ready() -> bool {
        if std::env::var_os(ENV).is_none_or(|v| v != "1") {
            eprintln!(
                "skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net` \
                 (cargo xtask bench)"
            );
            return false;
        }
        if !corerouter_hal_linux::mpls::available() {
            eprintln!("skipped: no kernel MPLS (modprobe mpls_router)");
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

    fn ip(args: &[&str]) {
        let out = Command::new("ip").args(args).output().unwrap();
        assert!(
            out.status.success(),
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn link(name: &str) -> (LinkAddr, [u8; 6]) {
        getifaddrs()
            .unwrap()
            .filter(|a| a.interface_name == name)
            .find_map(|a| {
                let l = *a.address?.as_link_addr()?;
                Some((l, l.addr()?))
            })
            .unwrap()
    }

    fn tx_packets(hal: &mut LinuxHal) -> u64 {
        hal.poll()
            .into_iter()
            .find(|l| l.name.as_str() == "to")
            .map(|l| l.tx_packets)
            .unwrap()
    }

    /// A 64-byte frame: label 100 (TTL 64, bottom) over IPv4/UDP.
    fn frame(dst_mac: [u8; 6], src_mac: [u8; 6], host: u8) -> Vec<u8> {
        let mut f = Vec::with_capacity(64);
        f.extend_from_slice(&dst_mac);
        f.extend_from_slice(&src_mac);
        f.extend_from_slice(&[0x88, 0x47]);
        f.extend_from_slice(&((100u32 << 12) | 0x100 | 64).to_be_bytes());
        let total: u16 = 64 - 14 - 4;
        let mut iph = vec![
            0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 200, 0, 2, 198, 18, 0, host,
        ];
        iph[2..4].copy_from_slice(&total.to_be_bytes());
        f.extend_from_slice(&iph);
        f.extend_from_slice(&40000u16.to_be_bytes());
        f.extend_from_slice(&(9000u16 + u16::from(host)).to_be_bytes());
        f.extend_from_slice(&(total - 20).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.resize(64, 0);
        f
    }

    struct Lab {
        sock: Socket,
        frames: Vec<Vec<u8>>,
        hal: LinuxHal,
    }

    impl Lab {
        fn new() -> Self {
            std::fs::write("/proc/sys/net/mpls/platform_labels", "1000").unwrap();
            ip(&["link", "add", "ta", "type", "veth", "peer", "name", "tb"]);
            ip(&["link", "add", "to", "type", "dummy"]);
            for d in ["ta", "tb", "to"] {
                ip(&["link", "set", d, "up"]);
            }
            std::fs::write("/proc/sys/net/mpls/conf/tb/input", "1").unwrap();
            ip(&["addr", "add", "10.201.0.1/24", "dev", "to"]);
            ip(&[
                "-f",
                "mpls",
                "route",
                "add",
                "100",
                "as",
                "200",
                "via",
                "inet",
                "10.201.0.2",
                "dev",
                "to",
            ]);
            let (ta, ta_mac) = link("ta");
            let (_, tb_mac) = link("tb");
            let sock = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0))).unwrap();
            bind(sock.as_raw_fd(), &ta).unwrap();
            let mut lab = Self {
                sock,
                frames: (0..=255u8).map(|h| frame(tb_mac, ta_mac, h)).collect(),
                hal: LinuxHal::with_policy(Policy {
                    manage: vec!["ta".into(), "tb".into(), "to".into()],
                    unmanaged: Vec::new(),
                }),
            };
            let (_, got) = lab.burst(BURST);
            assert!(got > BURST / 2, "only {got} of {BURST} frames switched");
            lab
        }

        /// Send `n` frames; the time until `to` sent all it will.
        fn burst(&mut self, n: u64) -> (Duration, u64) {
            let fd = self.sock.as_raw_fd();
            let before = tx_packets(&mut self.hal);
            let start = Instant::now();
            for i in 0..n {
                let _ = send(fd, &self.frames[(i % 256) as usize], MsgFlags::empty());
            }
            let mut last = tx_packets(&mut self.hal);
            loop {
                std::thread::sleep(Duration::from_micros(200));
                let now = tx_packets(&mut self.hal);
                if now == last || now - before >= n {
                    break;
                }
                last = now;
            }
            (start.elapsed(), tx_packets(&mut self.hal) - before)
        }
    }

    pub fn switch(c: &mut Criterion) {
        let mut lab = Lab::new();
        let mut g = c.benchmark_group("netns_mpls_ttl");
        g.throughput(Throughput::Elements(BURST));
        g.sample_size(30);
        g.bench_function("mpls64/no taps", |b| {
            b.iter_custom(|iters| (0..iters).map(|_| lab.burst(BURST).0).sum())
        });
        // The responder's three taps on the ingress port, as the daemon
        // keeps them (nobody reads: these frames all pass the filter by).
        let mut r = HostResponder::open().unwrap();
        assert!(r.set_interfaces(&["tb".parse().unwrap()]).is_empty());
        g.bench_function("mpls64/responder taps on the port", |b| {
            b.iter_custom(|iters| (0..iters).map(|_| lab.burst(BURST).0).sum())
        });
        g.finish();
        drop(r);
    }
}

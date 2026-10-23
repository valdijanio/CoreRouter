//! G1.26 — packets per second the kernel forwards, before and after
//! System › Tuning, inside a throwaway network namespace — no root,
//! nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- \
//!     cargo bench -p corerouter-hal-linux --bench netns_forward
//! ```
//!
//! UDP frames of 64 bytes, to 256 destinations, are written with
//! `AF_PACKET` into veth `fa`; they come in on its peer `fb`, are routed
//! (`ip_forward`) and leave by dummy `fo`, whose `tx_packets` count them.
//! Each iteration sends a burst and waits for the counter to settle;
//! criterion's elements/s is the forwarding rate. One CPU does it all
//! (veth hands the frame to the receive backlog of the sending CPU).
//!
//! A namespace has its own `rp_filter` and forwarding, but not the
//! host-wide `netdev_budget`/`netdev_max_backlog` (those need the real
//! host, as root: docs/tuning.md). So the "before" is the kernel's own
//! values here and the "after" is what the throughput profile changes in a
//! namespace, applied by `LinuxHal::apply` like the router does.

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
    linux::forward(&mut c);
    c.final_summary();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::AsRawFd;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use corerouter_hal::Hal;
    use corerouter_hal_linux::{LinuxHal, Policy};
    use corerouter_model::Config;
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

    /// Frames `fo` sent, over rtnetlink (`/sys/class/net` shows the
    /// namespace that mounted it, the host's).
    fn tx_packets(hal: &mut LinuxHal) -> u64 {
        hal.poll()
            .into_iter()
            .find(|l| l.name.as_str() == "fo")
            .map(|l| l.tx_packets)
            .unwrap()
    }

    fn checksum(words: &[u8]) -> u16 {
        let mut sum: u32 = words
            .chunks(2)
            .map(|c| u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)])))
            .sum();
        while sum > 0xffff {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// A 64-byte Ethernet/IPv4/UDP frame from 10.200.0.2 to 198.18.0.`host`.
    fn frame(dst_mac: [u8; 6], src_mac: [u8; 6], host: u8) -> Vec<u8> {
        let mut f = Vec::with_capacity(64);
        f.extend_from_slice(&dst_mac);
        f.extend_from_slice(&src_mac);
        f.extend_from_slice(&[0x08, 0x00]);
        let payload = 64 - 14 - 20 - 8;
        let total = (20 + 8 + payload) as u16;
        let mut iph = vec![
            0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 200, 0, 2, 198, 18, 0, host,
        ];
        iph[2..4].copy_from_slice(&total.to_be_bytes());
        let c = checksum(&iph);
        iph[10..12].copy_from_slice(&c.to_be_bytes());
        f.extend_from_slice(&iph);
        let udp_len = (8 + payload) as u16;
        f.extend_from_slice(&40000u16.to_be_bytes());
        f.extend_from_slice(&(9000u16 + u16::from(host)).to_be_bytes());
        f.extend_from_slice(&udp_len.to_be_bytes());
        f.extend_from_slice(&[0, 0]); // UDP checksum 0: none (IPv4)
        f.resize(64, 0);
        f
    }

    struct Lab {
        sock: Option<Socket>,
        frames: Vec<Vec<u8>>,
        hal: LinuxHal,
        applied: Config,
    }

    impl Lab {
        fn new() -> Self {
            Self {
                sock: None,
                frames: Vec::new(),
                // veth and dummy are managed only when listed.
                hal: LinuxHal::with_policy(Policy {
                    manage: vec!["fa".into(), "fb".into(), "fo".into()],
                    unmanaged: Vec::new(),
                }),
                applied: Config::default(),
            }
        }

        /// Apply `values` like the router does, then make the links again:
        /// an interface takes `conf.default.*` when it is created, and the
        /// kernel uses the larger `rp_filter` of `all` and the interface.
        fn tune(&mut self, values: &[(&str, i64)], ports: &[(&str, &str, i64)]) {
            let mut to = Config::default();
            for (n, v) in values {
                to.system.tuning.sysctl.insert((*n).to_owned(), *v);
            }
            // The links are made again below: no port settings until then.
            self.hal.apply(&self.applied, &to).unwrap();
            self.applied = to.clone();
            self.sock = None;
            let _ = Command::new("ip").args(["link", "del", "fa"]).output();
            let _ = Command::new("ip").args(["link", "del", "fo"]).output();
            ip(&["link", "add", "fa", "type", "veth", "peer", "name", "fb"]);
            ip(&["link", "add", "fo", "type", "dummy"]);
            for d in ["fa", "fb", "fo"] {
                ip(&["link", "set", d, "up"]);
            }
            ip(&["addr", "add", "10.200.0.1/24", "dev", "fb"]);
            ip(&["addr", "add", "10.201.0.1/24", "dev", "fo"]);
            ip(&["route", "add", "198.18.0.0/15", "dev", "fo"]);
            let (fa, fa_mac) = link("fa");
            let (_, fb_mac) = link("fb");
            let sock = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0))).unwrap();
            bind(sock.as_raw_fd(), &fa).unwrap();
            self.frames = (0..=255u8).map(|h| frame(fb_mac, fa_mac, h)).collect();
            self.sock = Some(sock);
            // Port settings (G1.26b) on the fresh links.
            for (port, key, v) in ports {
                to.system
                    .tuning
                    .ports
                    .entry(port.parse().unwrap())
                    .or_default()
                    .insert((*key).to_owned(), *v);
            }
            self.hal.apply(&self.applied, &to).unwrap();
            self.applied = to;
            self.burst(BURST); // warm the route and neighbor caches
        }

        /// Send `n` frames; the time until `fo` forwarded all it will.
        fn burst(&mut self, n: u64) -> (Duration, u64) {
            let fd = self.sock.as_ref().unwrap().as_raw_fd();
            let before = tx_packets(&mut self.hal);
            let start = Instant::now();
            for i in 0..n {
                let f = &self.frames[(i % 256) as usize];
                // ENOBUFS: the qdisc of fa is full; try the next one.
                let _ = send(fd, f, MsgFlags::empty());
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

    pub fn forward(c: &mut Criterion) {
        let mut lab = Lab::new();
        let mut g = c.benchmark_group("netns_forward");
        g.throughput(Throughput::Elements(BURST));
        g.sample_size(20);
        // A common distribution default (strict reverse path filter).
        lab.tune(
            &[
                ("net.ipv4.ip_forward", 1),
                ("net.ipv4.conf.all.rp_filter", 1),
                ("net.ipv4.conf.default.rp_filter", 1),
            ],
            &[],
        );
        g.bench_function("udp64/before (rp_filter strict)", |b| {
            b.iter_custom(|iters| (0..iters).map(|_| lab.burst(BURST).0).sum())
        });
        let (_, got) = lab.burst(BURST);
        eprintln!("before: {got} of {BURST} frames forwarded");
        // What the throughput profile sets in a namespace.
        let profile = [
            ("net.ipv4.ip_forward", 1),
            ("net.ipv4.conf.all.rp_filter", 0),
            ("net.ipv4.conf.default.rp_filter", 0),
            ("net.ipv4.fib_multipath_hash_policy", 1),
        ];
        lab.tune(&profile, &[]);
        g.bench_function("udp64/after (throughput profile)", |b| {
            b.iter_custom(|iters| (0..iters).map(|_| lab.burst(BURST).0).sum())
        });
        let (_, got) = lab.burst(BURST);
        eprintln!("after: {got} of {BURST} frames forwarded");
        // G1.26b: the egress port's root qdisc. A dummy (or veth) has
        // `noqueue`; fq_codel, the AQM the profile gives a single-queue
        // NIC, costs some per-packet work.
        lab.tune(&profile, &[("fo", "qdisc", 0)]);
        g.bench_function("udp64/after + fq_codel on the egress port", |b| {
            b.iter_custom(|iters| (0..iters).map(|_| lab.burst(BURST).0).sum())
        });
        let (_, got) = lab.burst(BURST);
        eprintln!("after + fq_codel: {got} of {BURST} frames forwarded");
        g.finish();
    }
}

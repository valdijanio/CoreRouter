//! G2.1c — what `/ip firewall raw` `notrack` saves: packets per second
//! the kernel forwards with connection tracking, and with the same flows
//! marked `notrack` in raw `prerouting`, inside a throwaway network
//! namespace (no root, nothing reaches the host):
//!
//! ```sh
//! COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- \
//!     cargo bench -p corerouter-hal-linux --bench netns_raw
//! ```
//!
//! The lab of `netns_forward`: 64-byte UDP frames written with
//! `AF_PACKET` into veth `fa`, routed from `fb` to dummy `fo`, counted by
//! `fo`'s `tx_packets`. 4096 flows (256 destinations × 16 source ports).
//! The rulesets go through `LinuxHal::apply`, as the router applies them:
//!
//! - `conntrack`: filter forward accepts `new,established,untracked`
//!   (a `ct state` match: every packet is looked up in conntrack);
//! - `raw notrack`: the same, plus raw prerouting `notrack` for UDP;
//! - `raw drop` / `filter drop`: the flows dropped in raw prerouting or in
//!   filter forward (after conntrack made an entry): drops per second.

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
    linux::raw(&mut c);
    c.final_summary();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::AsRawFd;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use corerouter_firewall::sample::{act, m, rule};
    use corerouter_hal::Hal;
    use corerouter_hal_linux::{LinuxHal, Policy};
    use corerouter_model::Config;
    use corerouter_model::firewall::Action;
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

    /// A 64-byte Ethernet/IPv4/UDP frame from 10.200.0.2:`sport` to
    /// 198.18.0.`host`.
    fn frame(dst_mac: [u8; 6], src_mac: [u8; 6], host: u8, sport: u16) -> Vec<u8> {
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
        f.extend_from_slice(&sport.to_be_bytes());
        f.extend_from_slice(&(9000u16 + u16::from(host)).to_be_bytes());
        f.extend_from_slice(&udp_len.to_be_bytes());
        f.extend_from_slice(&[0, 0]); // UDP checksum 0: none (IPv4)
        f.resize(64, 0);
        f
    }

    /// Packets dropped by the kernel rule tagged `cr:*N` (its counter),
    /// read with `nft` (the bench is not about how counters are read).
    fn dropped(tag: &str) -> u64 {
        let out = Command::new("nft")
            .args(["-j", "list", "table", "inet", "corerouter"])
            .output()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|o| o.get("rule"))
            .filter(|r| r["comment"] == tag)
            .flat_map(|r| r["expr"].as_array().cloned().unwrap_or_default())
            .filter_map(|e| e.get("counter").and_then(|c| c["packets"].as_u64()))
            .sum()
    }

    struct Lab {
        sock: Socket,
        frames: Vec<Vec<u8>>,
        hal: LinuxHal,
        applied: Config,
    }

    impl Lab {
        fn new() -> Self {
            let mut hal = LinuxHal::with_policy(Policy {
                manage: vec!["fa".into(), "fb".into(), "fo".into()],
                unmanaged: Vec::new(),
            });
            let mut base = Config::default();
            for (k, v) in [
                ("net.ipv4.ip_forward", 1),
                ("net.ipv4.conf.all.rp_filter", 0),
                ("net.ipv4.conf.default.rp_filter", 0),
            ] {
                base.system.tuning.sysctl.insert(k.to_owned(), v);
            }
            hal.apply(&Config::default(), &base).unwrap();
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
            let frames = (0..=255u8)
                .flat_map(|h| (0..16u16).map(move |p| (h, 40_000 + p)))
                .map(|(h, p)| frame(fb_mac, fa_mac, h, p))
                .collect();
            Self {
                sock,
                frames,
                hal,
                applied: base,
            }
        }

        /// Apply the firewall of `rules` (filter, raw) like the router.
        fn firewall(
            &mut self,
            filter: Vec<corerouter_model::firewall::FirewallRule>,
            raw: Vec<corerouter_model::firewall::FirewallRule>,
        ) {
            let mut to = self.applied.clone();
            to.ip.firewall.filter = filter.into();
            to.ip.firewall.raw = raw.into();
            self.hal.apply(&self.applied, &to).unwrap();
            self.applied = to;
            self.burst(BURST); // warm the caches and the conntrack entries
        }

        fn send_all(&self, n: u64) -> Instant {
            let fd = self.sock.as_raw_fd();
            let start = Instant::now();
            for i in 0..n {
                let f = &self.frames[(i % self.frames.len() as u64) as usize];
                // ENOBUFS: the qdisc of fa is full; try the next one.
                let _ = send(fd, f, MsgFlags::empty());
            }
            start
        }

        /// Send `n` frames; the time until `fo` forwarded all it will.
        fn burst(&mut self, n: u64) -> (Duration, u64) {
            let before = tx_packets(&mut self.hal);
            let start = self.send_all(n);
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

        /// Send `n` frames that rule `tag` drops; the time until its
        /// counter settles.
        fn drop_burst(&mut self, n: u64, tag: &str) -> Duration {
            let before = dropped(tag);
            let start = self.send_all(n);
            let mut last = dropped(tag);
            loop {
                std::thread::sleep(Duration::from_micros(500));
                let now = dropped(tag);
                if now == last || now - before >= n {
                    break;
                }
                last = now;
            }
            start.elapsed()
        }
    }

    pub fn raw(c: &mut Criterion) {
        let mut lab = Lab::new();
        let mut g = c.benchmark_group("netns_raw");
        g.throughput(Throughput::Elements(BURST));
        g.sample_size(20);
        let tracked = || {
            vec![
                rule(
                    1,
                    "forward",
                    m(&[("connection_state", "new,established,untracked")]).unwrap(),
                    Action::Accept,
                )
                .unwrap(),
            ]
        };
        lab.firewall(tracked(), vec![]);
        g.bench_function("udp64/conntrack", |b| {
            b.iter_custom(|iters| (0..iters).map(|_| lab.burst(BURST).0).sum())
        });
        eprintln!("conntrack: {} of {BURST} forwarded", lab.burst(BURST).1);
        let notrack = vec![
            rule(
                2,
                "prerouting",
                m(&[("protocol", "udp")]).unwrap(),
                act(r#"{"type":"notrack"}"#).unwrap(),
            )
            .unwrap(),
        ];
        lab.firewall(tracked(), notrack);
        g.bench_function("udp64/raw notrack", |b| {
            b.iter_custom(|iters| (0..iters).map(|_| lab.burst(BURST).0).sum())
        });
        eprintln!("raw notrack: {} of {BURST} forwarded", lab.burst(BURST).1);

        let drop = |id, chain: &str| {
            vec![rule(id, chain, m(&[("protocol", "udp")]).unwrap(), Action::Drop).unwrap()]
        };
        let mut filter = tracked();
        filter.splice(0..0, drop(3, "forward"));
        lab.firewall(filter, vec![]);
        g.bench_function("udp64/filter drop (after conntrack)", |b| {
            b.iter_custom(|iters| (0..iters).map(|_| lab.drop_burst(BURST, "cr:*3")).sum())
        });
        lab.firewall(tracked(), drop(4, "prerouting"));
        g.bench_function("udp64/raw drop (before conntrack)", |b| {
            b.iter_custom(|iters| (0..iters).map(|_| lab.drop_burst(BURST, "cr:*4")).sum())
        });
        g.finish();
    }
}

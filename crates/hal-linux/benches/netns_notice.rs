//! G4.10b — the subscriber notices' cost in the kernel, inside a throwaway
//! network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- \
//!     cargo bench -p corerouter-hal-linux --bench netns_notice
//! ```
//!
//! - **per packet:** 64-byte UDP frames from a subscriber who is *not* in a
//!   list (the common case) are forwarded fa → fb → fo, with no firewall,
//!   with 100 000 subscribers in an address list and no notice, and with
//!   the same list behind a block profile (the `notice_*` chains), and the
//!   last two again with a masquerade rule (connection tracking on, as on
//!   an ISP's router: the notice's nat chain turns it on by itself); the
//!   frames a member sends would be refused, so they are not counted;
//! - **update:** how long one subscriber entering the list takes with
//!   100 000 already in it (one dynamic element, `nft add element`), and
//!   how long the whole table takes to load (a commit that changes static
//!   entries replaces it).
//!
//! One CPU does it all (veth hands the frame to the sending CPU's backlog).

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
    linux::notice(&mut c);
    c.final_summary();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::net::Ipv4Addr;
    use std::os::fd::AsRawFd;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use corerouter_hal::{DynamicChange, Hal};
    use corerouter_hal_linux::{LinuxHal, Policy};
    use corerouter_model::firewall::{AddrMatch, AddressListEntry, DynamicAddress};
    use corerouter_model::subscriber_notice::{Mode, Profile};
    use corerouter_model::{Config, ItemId};
    use criterion::{Criterion, Throughput};
    use nix::ifaddrs::getifaddrs;
    use nix::sys::socket::{LinkAddr, MsgFlags, bind, send};
    use socket2::{Domain, Protocol, Socket, Type};

    const ENV: &str = "COREROUTER_NETNS_BENCH";
    /// Frames per iteration.
    const BURST: u64 = 20_000;
    /// Subscribers in the list.
    const LISTED: u32 = 100_000;

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

    /// The base config of every case: forwarding, no reverse-path filter.
    fn base() -> Config {
        let mut c = Config::default();
        for (k, v) in [
            ("net.ipv4.ip_forward", 1),
            ("net.ipv4.conf.all.rp_filter", 0),
            ("net.ipv4.conf.default.rp_filter", 0),
        ] {
            c.system.tuning.sysctl.insert(k.to_owned(), v);
        }
        c
    }

    /// `LISTED` subscribers of 100.64.0.0/10 in list `bloqueados`; with a
    /// block profile on it when `notice`.
    fn listed(notice: bool) -> Config {
        listed_nat(notice, false)
    }

    /// `listed`, with a masquerade rule on `fo` when `nat` (connection
    /// tracking on, as on every ISP router: the notice's nat chain turns it
    /// on too, so this is the fair "before").
    fn listed_nat(notice: bool, nat: bool) -> Config {
        let mut c = base();
        if nat {
            c.ip.firewall.nat.push(
                corerouter_firewall::sample::rule(
                    1,
                    "srcnat",
                    corerouter_firewall::sample::m(&[("out_interface", "fo")]).unwrap(),
                    corerouter_firewall::sample::act(r#"{"type":"masquerade"}"#).unwrap(),
                )
                .unwrap(),
            );
        }
        let fw = &mut *c.ip.firewall;
        for i in 0..LISTED {
            fw.address_lists.push(AddressListEntry {
                id: ItemId(i + 1),
                list: "bloqueados".parse().unwrap(),
                address: AddrMatch::Net(
                    std::net::IpAddr::V4(Ipv4Addr::from(0x6440_0000 + i)).into(),
                ),
                disabled: false,
                comment: String::new(),
            });
        }
        if notice {
            c.ip.subscriber_notice.profiles.push(Profile::new(
                ItemId(1),
                "atraso".parse().unwrap(),
                Mode::Block,
                "bloqueados".parse().unwrap(),
            ));
        }
        c
    }

    struct Lab {
        sock: Socket,
        frames: Vec<Vec<u8>>,
        hal: LinuxHal,
        applied: Config,
    }

    impl Lab {
        fn new() -> Self {
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
            Self {
                sock,
                frames: (0..=255u8).map(|h| frame(fb_mac, fa_mac, h)).collect(),
                hal: LinuxHal::with_policy(Policy {
                    manage: vec!["fa".into(), "fb".into(), "fo".into()],
                    unmanaged: Vec::new(),
                }),
                applied: Config::default(),
            }
        }

        /// Apply `to`; how long the kernel took.
        fn set(&mut self, to: Config) -> Duration {
            let start = Instant::now();
            self.hal.apply(&self.applied, &to).unwrap();
            let took = start.elapsed();
            self.applied = to;
            self.burst(BURST); // warm
            took
        }

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

    pub fn notice(c: &mut Criterion) {
        let mut lab = Lab::new();
        let mut g = c.benchmark_group("netns_notice");
        g.throughput(Throughput::Elements(BURST));
        g.sample_size(15);
        for (name, cfg) in [
            ("udp64/no firewall", base()),
            ("udp64/100k listed, no notice", listed(false)),
            (
                "udp64/100k listed, block profile (non-member)",
                listed(true),
            ),
            (
                "udp64/100k listed, masquerade (conntrack on)",
                listed_nat(false, true),
            ),
            (
                "udp64/100k listed, masquerade + block profile (non-member)",
                listed_nat(true, true),
            ),
        ] {
            let took = lab.set(cfg);
            eprintln!("{name}: applied in {took:?}");
            g.bench_function(name, |b| {
                b.iter_custom(|iters| (0..iters).map(|_| lab.burst(BURST).0).sum())
            });
            let (_, got) = lab.burst(BURST);
            eprintln!("{name}: {got} of {BURST} frames forwarded");
        }
        // One subscriber in and out of the list, 100 000 already in it.
        g.throughput(Throughput::Elements(1));
        g.sample_size(30);
        let mut k = 0u32;
        g.bench_function(
            "update/one subscriber enters and leaves (100k listed)",
            |b| {
                b.iter(|| {
                    k = k.wrapping_add(1);
                    let d = DynamicAddress {
                        list: "bloqueados".parse().unwrap(),
                        address: AddrMatch::Net(
                            std::net::IpAddr::V4(Ipv4Addr::from(0x6480_0000 + (k % 60_000))).into(),
                        ),
                        timeout_secs: 3600,
                        added_by_rule: false,
                    };
                    lab.hal
                        .address_list_dynamic(DynamicChange::Add(&d))
                        .unwrap();
                    lab.hal
                        .address_list_dynamic(DynamicChange::Remove(&d))
                        .unwrap();
                })
            },
        );
        g.finish();
        let took = lab.set(base());
        eprintln!("teardown: {took:?}");
        lab.hal.apply(&lab.applied, &Config::default()).unwrap();
    }
}

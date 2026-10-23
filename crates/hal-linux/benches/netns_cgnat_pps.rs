//! G2.3e — packets per second through the CGNAT, with and without the
//! fast path (G2.4), and new connections per second, inside throwaway
//! network namespaces — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- \
//!     cargo bench -p corerouter-hal-linux --bench netns_cgnat_pps
//! ```
//!
//! ```text
//!  AF_PACKET → fa ─veth─ fb [this ns: CGNAT] fo ─veth─ fp [server ns]
//!  100.64.0.h:40000 → 198.18.0.h:(9000+h)     counts fo tx   AF_PACKET replies
//! ```
//!
//! 64-byte UDP frames of 256 subscribers (one flow each) are written into
//! veth `fa`; they come in on `fb`, are translated by the pool (or only
//! routed, for the baseline) and leave by `fo`, whose `tx_packets` count
//! them. Before measuring, every flow gets one reply, written with
//! `AF_PACKET` into `fp` from the conntrack's reply tuple: a UDP flow is
//! `established` only after its reply, and only then enters the flowtable.
//! One CPU does it all (veth hands the frame to the sending CPU's backlog):
//! the numbers compare configurations on one core, they are not a NIC's.

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
    linux::pps(&mut c);
    c.final_summary();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::fd::AsRawFd;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use corerouter_hal::Hal;
    use corerouter_hal::conntrack::status;
    use corerouter_hal_linux::{LinuxHal, Policy, ctnl};
    use corerouter_model::Config;
    use corerouter_model::cgnat::Pool;
    use criterion::{Criterion, Throughput};
    use nix::ifaddrs::getifaddrs;
    use nix::sys::socket::{LinkAddr, MsgFlags, bind, send};
    use socket2::{Domain, Protocol, Socket, Type};

    const ENV: &str = "COREROUTER_NETNS_BENCH";
    /// Frames per iteration.
    const BURST: u64 = 20_000;
    /// Subscribers, one flow each.
    const FLOWS: u8 = 255;

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

    fn run(cmd: &mut Command) {
        let out = cmd.output().unwrap();
        assert!(
            out.status.success(),
            "{cmd:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn ip(args: &[&str]) {
        run(Command::new("ip").args(args));
    }

    /// The server's namespace: a child `unshare --net` (no root needed
    /// inside our user namespace).
    struct Ns(Child);

    impl Ns {
        fn new() -> Self {
            let child = Command::new("unshare")
                .args(["--net", "--", "sleep", "3600"])
                .stdin(Stdio::null())
                .spawn()
                .unwrap();
            let ns = Ns(child);
            let mine = std::fs::read_link("/proc/self/ns/net").unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            while std::fs::read_link(format!("/proc/{}/ns/net", ns.pid())).ok() == Some(mine.clone())
            {
                assert!(Instant::now() < deadline, "unshare --net did not start");
                std::thread::sleep(Duration::from_millis(10));
            }
            ns
        }

        fn pid(&self) -> String {
            self.0.id().to_string()
        }

        fn ip(&self, args: &[&str]) {
            let pid = self.pid();
            run(Command::new("nsenter")
                .args(["-t", pid.as_str(), "-n", "ip"])
                .args(args));
        }

        fn within<T: Send + 'static>(&self, f: impl FnOnce() -> T + Send + 'static) -> T {
            let pid = self.pid();
            std::thread::spawn(move || {
                let ns = std::fs::File::open(format!("/proc/{pid}/ns/net")).unwrap();
                nix::sched::setns(ns, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
                f()
            })
            .join()
            .unwrap()
        }
    }

    impl Drop for Ns {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
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

    /// A 64-byte Ethernet/IPv4/UDP frame.
    fn frame(dst_mac: [u8; 6], src_mac: [u8; 6], src: (Ipv4Addr, u16), dst: (Ipv4Addr, u16)) -> Vec<u8> {
        let mut f = Vec::with_capacity(64);
        f.extend_from_slice(&dst_mac);
        f.extend_from_slice(&src_mac);
        f.extend_from_slice(&[0x08, 0x00]);
        let payload = 64 - 14 - 20 - 8;
        let total = (20 + 8 + payload) as u16;
        let mut iph = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 17, 0, 0];
        iph.extend_from_slice(&src.0.octets());
        iph.extend_from_slice(&dst.0.octets());
        iph[2..4].copy_from_slice(&total.to_be_bytes());
        let c = checksum(&iph);
        iph[10..12].copy_from_slice(&c.to_be_bytes());
        f.extend_from_slice(&iph);
        f.extend_from_slice(&src.1.to_be_bytes());
        f.extend_from_slice(&dst.1.to_be_bytes());
        f.extend_from_slice(&((8 + payload) as u16).to_be_bytes());
        f.extend_from_slice(&[0, 0]); // no UDP checksum (IPv4)
        f.resize(64, 0);
        f
    }

    fn subscriber(h: u8) -> Ipv4Addr {
        Ipv4Addr::new(100, 64, 0, h)
    }

    fn far_end(h: u8) -> (Ipv4Addr, u16) {
        (Ipv4Addr::new(198, 18, 0, h), 9000 + u16::from(h))
    }

    #[derive(Clone, Copy, PartialEq)]
    enum Mode {
        Route,
        Cgnat,
        CgnatFastPath,
    }

    fn config(mode: Mode) -> Config {
        let mut c = Config::default();
        if mode == Mode::Route {
            return c;
        }
        let p: Pool = serde_json::from_value(serde_json::json!({
            "id": "*1", "name": "bench", "inside": ["100.64.0.0/24"], "outside": ["203.0.113.0/28"],
            "ports_per_subscriber": 1000,
        }))
        .unwrap();
        c.ip.cgnat.pools = vec![p];
        if mode == Mode::CgnatFastPath {
            c.ip.fastpath.enabled = true;
            c.ip.fastpath.interfaces = vec!["fb".parse().unwrap(), "fo".parse().unwrap()];
        }
        c
    }

    struct Lab {
        _server: Ns,
        tx: Socket,
        reply: Socket,
        hal: LinuxHal,
        applied: Config,
        flows: Vec<Vec<u8>>,
        fa_mac: [u8; 6],
        fb_mac: [u8; 6],
        fo_mac: [u8; 6],
        fp_mac: [u8; 6],
        /// Source port of the next new connection (`new` burst).
        next_port: u32,
    }

    impl Lab {
        fn new() -> Self {
            let server = Ns::new();
            ip(&["link", "set", "lo", "up"]);
            ip(&["link", "add", "fa", "type", "veth", "peer", "name", "fb"]);
            ip(&["link", "add", "fo", "type", "veth", "peer", "name", "fp", "netns", &server.pid()]);
            for d in ["fa", "fb", "fo"] {
                ip(&["link", "set", d, "up"]);
            }
            std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
            for k in ["all", "default", "fb", "fo"] {
                let _ = std::fs::write(format!("/proc/sys/net/ipv4/conf/{k}/rp_filter"), "0");
            }
            ip(&["addr", "add", "100.64.0.254/24", "dev", "fb"]);
            ip(&["addr", "add", "192.0.2.1/24", "dev", "fo"]);
            server.ip(&["link", "set", "lo", "up"]);
            server.ip(&["addr", "add", "192.0.2.2/24", "dev", "fp"]);
            server.ip(&["link", "set", "fp", "up"]);
            ip(&["route", "add", "198.18.0.0/15", "via", "192.0.2.2"]);
            let (fa, fa_mac) = link("fa");
            let (_, fb_mac) = link("fb");
            let (_, fo_mac) = link("fo");
            // The answers back to the subscribers leave by fb: no ARP for them.
            for h in 1..=FLOWS {
                let mac = fa_mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
                ip(&["neigh", "replace", &subscriber(h).to_string(), "lladdr", &mac, "dev", "fb"]);
            }
            let (fp_mac, reply) = server.within(|| {
                let (fp, fp_mac) = link("fp");
                let s = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0))).unwrap();
                bind(s.as_raw_fd(), &fp).unwrap();
                (fp_mac, s)
            });
            // The server's address must be resolved before a flow can be
            // offloaded (the flowtable keeps the next hop's MAC).
            let mac = fp_mac.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":");
            ip(&["neigh", "replace", "192.0.2.2", "lladdr", &mac, "dev", "fo"]);
            let tx = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0))).unwrap();
            bind(tx.as_raw_fd(), &fa).unwrap();
            let flows = (1..=FLOWS)
                .map(|h| frame(fb_mac, fa_mac, (subscriber(h), 40000), far_end(h)))
                .collect();
            Self {
                _server: server,
                tx,
                reply,
                hal: LinuxHal::with_policy(Policy {
                    manage: vec!["fa".into(), "fb".into(), "fo".into()],
                    unmanaged: Vec::new(),
                }),
                applied: Config::default(),
                flows,
                fa_mac,
                fb_mac,
                fo_mac,
                fp_mac,
                next_port: 0,
            }
        }

        fn tx_packets(&mut self) -> u64 {
            self.hal
                .poll()
                .into_iter()
                .find(|l| l.name.as_str() == "fo")
                .map(|l| l.tx_packets)
                .unwrap()
        }

        /// Send `frames` (round robin, `n` in all); the time until `fo`
        /// forwarded all it will, and how many it did.
        fn send(&mut self, n: u64, mut frame: impl FnMut(u64) -> Vec<u8>) -> (Duration, u64) {
            let fd = self.tx.as_raw_fd();
            let before = self.tx_packets();
            let start = Instant::now();
            for i in 0..n {
                // ENOBUFS: fa's queue is full; go on.
                let _ = send(fd, &frame(i), MsgFlags::empty());
            }
            let mut last = self.tx_packets();
            loop {
                std::thread::sleep(Duration::from_micros(200));
                let now = self.tx_packets();
                if now == last || now - before >= n {
                    break;
                }
                last = now;
            }
            (start.elapsed(), self.tx_packets() - before)
        }

        fn burst(&mut self, n: u64) -> (Duration, u64) {
            let flows = std::mem::take(&mut self.flows);
            let out = self.send(n, |i| flows[(i % u64::from(FLOWS)) as usize].clone());
            self.flows = flows;
            out
        }

        /// `n` frames, each one a connection never seen (a new source
        /// port of one of the subscribers).
        fn new_connections(&mut self, n: u64) -> (Duration, u64) {
            let (fb, fa) = (self.fb_mac, self.fa_mac);
            let base = self.next_port;
            self.next_port = self.next_port.wrapping_add(n as u32);
            self.send(n, move |i| {
                let k = base.wrapping_add(i as u32);
                let h = 1 + (k % u32::from(FLOWS)) as u8;
                let port = 1024 + ((k / u32::from(FLOWS)) % 60_000) as u16;
                frame(fb, fa, (subscriber(h), port), far_end(h))
            })
        }

        /// Configure `mode` and make every flow established: one packet
        /// out, its reply back (from the conntrack's reply tuple), one
        /// more out (which enters the flowtable when it is on).
        fn set(&mut self, mode: Mode) {
            let to = config(mode);
            self.hal.apply(&self.applied, &to).unwrap();
            self.applied = to;
            // Twice: a frame lost to a full queue would leave its flow out.
            self.burst(u64::from(FLOWS) * 2);
            if mode != Mode::Route {
                let conns = ctnl::dump().unwrap();
                let mut replies = 0;
                for c in conns.iter().filter(|c| c.protocol == 17 && c.orig.src_port == 40000) {
                    let (IpAddr::V4(src), IpAddr::V4(dst)) = (c.reply.src, c.reply.dst) else {
                        continue;
                    };
                    let f = frame(self.fo_mac, self.fp_mac, (src, c.reply.src_port), (dst, c.reply.dst_port));
                    let _ = send(self.reply.as_raw_fd(), &f, MsgFlags::empty());
                    replies += 1;
                }
                assert!(replies >= usize::from(FLOWS) * 9 / 10, "{replies} replies for {FLOWS} flows");
                std::thread::sleep(Duration::from_millis(50));
            }
            self.burst(u64::from(FLOWS) * 4);
            self.burst(BURST); // warm
            if mode == Mode::CgnatFastPath {
                let offloaded = ctnl::dump()
                    .unwrap()
                    .iter()
                    .filter(|c| c.orig.src_port == 40000 && c.has(status::OFFLOAD))
                    .count();
                eprintln!("{offloaded} of {FLOWS} flows in the flowtable");
                assert!(offloaded > usize::from(FLOWS) / 2, "the flows entered the flowtable");
            }
        }
    }

    pub fn pps(c: &mut Criterion) {
        let mut lab = Lab::new();
        let mut g = c.benchmark_group("netns_cgnat_pps");
        g.throughput(Throughput::Elements(BURST));
        g.sample_size(15);
        for (mode, name) in [
            (Mode::Route, "udp64/route only (no conntrack)"),
            (Mode::Cgnat, "udp64/cgnat"),
            (Mode::CgnatFastPath, "udp64/cgnat + fast path (software)"),
        ] {
            lab.set(mode);
            g.bench_function(name, |b| {
                b.iter_custom(|iters| (0..iters).map(|_| lab.burst(BURST).0).sum())
            });
            let (_, got) = lab.burst(BURST);
            eprintln!("{name}: {got} of {BURST} frames forwarded");
        }
        // Connection setup: every frame a new connection through the NAT.
        lab.set(Mode::Cgnat);
        g.bench_function("udp64/new connection each frame (cgnat)", |b| {
            b.iter_custom(|iters| (0..iters).map(|_| lab.new_connections(BURST).0).sum())
        });
        let (_, got) = lab.new_connections(BURST);
        eprintln!("new connections: {got} of {BURST} frames forwarded");
        g.finish();
        lab.hal.apply(&lab.applied, &Config::default()).unwrap();
    }
}

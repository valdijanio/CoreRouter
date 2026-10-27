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
    /// New connections per iteration of the setup benchmark.
    const NEW: u64 = 5_000;
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
            while std::fs::read_link(format!("/proc/{}/ns/net", ns.pid())).ok()
                == Some(mine.clone())
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
    fn frame(
        dst_mac: [u8; 6],
        src_mac: [u8; 6],
        src: (Ipv4Addr, u16),
        dst: (Ipv4Addr, u16),
    ) -> Vec<u8> {
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
        /// The pool without endpoint-independent mapping (no dynamic set
        /// updated per connection).
        CgnatNoEim,
        /// Conntrack without NAT (the fast path's table alone turns the
        /// connection tracking on): the cost of a new connection itself.
        ConntrackOnly,
        /// The pool without the G2.7 exhaustion chain (`icmp_unreachable`
        /// off): the "before" of its cost.
        CgnatNoIcmp,
        /// The exhaustion chain with 4096 other subscribers in set `full`
        /// (none of the measured ones).
        CgnatFullOthers,
        /// 64 ports per subscriber, for the exhaustion group.
        Exhaust,
    }

    fn config(mode: Mode) -> Config {
        let mut c = Config::default();
        if mode == Mode::Route {
            return c;
        }
        if mode == Mode::ConntrackOnly {
            c.ip.fastpath.enabled = true;
            c.ip.fastpath.hw_offload = corerouter_model::fastpath::HwOffload::No;
            c.ip.fastpath.interfaces = vec!["fb".parse().unwrap(), "fo".parse().unwrap()];
            return c;
        }
        let p: Pool = serde_json::from_value(serde_json::json!({
            "id": "*1", "name": "bench", "inside": ["100.64.0.0/24"], "outside": ["203.0.113.0/28"],
            "ports_per_subscriber": if mode == Mode::Exhaust { 64 } else { 1000 },
            "endpoint_independent_mapping": mode != Mode::CgnatNoEim && mode != Mode::Exhaust,
        }))
        .unwrap();
        c.ip.cgnat.pools = vec![p];
        c.ip.cgnat.settings.icmp_unreachable = mode != Mode::CgnatNoIcmp;
        // The latency samples must not wait for the limiter.
        c.ip.cgnat.settings.icmp_rate = 100;
        if mode == Mode::CgnatFastPath {
            c.ip.fastpath.enabled = true;
            c.ip.fastpath.interfaces = vec!["fb".parse().unwrap(), "fo".parse().unwrap()];
        }
        c
    }

    pub struct Lab {
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
            ip(&[
                "link",
                "add",
                "fo",
                "type",
                "veth",
                "peer",
                "name",
                "fp",
                "netns",
                &server.pid(),
            ]);
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
                let mac = fa_mac
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":");
                ip(&[
                    "neigh",
                    "replace",
                    &subscriber(h).to_string(),
                    "lladdr",
                    &mac,
                    "dev",
                    "fb",
                ]);
            }
            let (fp_mac, reply) = server.within(|| {
                let (fp, fp_mac) = link("fp");
                let s = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0))).unwrap();
                bind(s.as_raw_fd(), &fp).unwrap();
                (fp_mac, s)
            });
            // The server's address must be resolved before a flow can be
            // offloaded (the flowtable keeps the next hop's MAC).
            let mac = fp_mac
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<Vec<_>>()
                .join(":");
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

        /// Forget the connections the setup benchmark made (untimed), so
        /// every round starts with the slots as empty as a router's are.
        fn forget_new(&mut self) {
            let conns = ctnl::dump().unwrap();
            let new: Vec<_> = conns
                .into_iter()
                .filter(|c| c.orig.src_port != 40000)
                .collect();
            let _ = ctnl::delete(&new);
        }

        /// Configure `mode` and make every flow established: one packet
        /// out, its reply back (from the conntrack's reply tuple), one
        /// more out (which enters the flowtable when it is on).
        fn set(&mut self, mode: Mode) {
            let to = config(mode);
            self.hal.apply(&self.applied, &to).unwrap();
            self.applied = to;
            if mode == Mode::CgnatFullOthers {
                let others: Vec<Ipv4Addr> = (0..4096u32)
                    .map(|i| Ipv4Addr::from(0x6440_1000 + i))
                    .collect();
                self.hal.cgnat_full(&others).unwrap();
            }
            if mode == Mode::Exhaust {
                return;
            }
            // Twice: a frame lost to a full queue would leave its flow out.
            self.burst(u64::from(FLOWS) * 2);
            if mode != Mode::Route {
                let conns = ctnl::dump().unwrap();
                let mut replies = 0;
                for c in conns
                    .iter()
                    .filter(|c| c.protocol == 17 && c.orig.src_port == 40000)
                {
                    let (IpAddr::V4(src), IpAddr::V4(dst)) = (c.reply.src, c.reply.dst) else {
                        continue;
                    };
                    let f = frame(
                        self.fo_mac,
                        self.fp_mac,
                        (src, c.reply.src_port),
                        (dst, c.reply.dst_port),
                    );
                    let _ = send(self.reply.as_raw_fd(), &f, MsgFlags::empty());
                    replies += 1;
                }
                assert!(
                    replies >= usize::from(FLOWS) * 9 / 10,
                    "{replies} replies for {FLOWS} flows"
                );
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
                assert!(
                    offloaded > usize::from(FLOWS) / 2,
                    "the flows entered the flowtable"
                );
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
            (
                Mode::CgnatNoIcmp,
                "udp64/cgnat without the exhaustion chain",
            ),
            (Mode::Cgnat, "udp64/cgnat"),
            (Mode::CgnatFullOthers, "udp64/cgnat, 4096 others in full"),
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
        g.sample_size(10);
        g.throughput(Throughput::Elements(NEW));
        for (mode, name) in [
            (
                Mode::CgnatNoIcmp,
                "udp64/new connection each frame (cgnat without the exhaustion chain)",
            ),
            (Mode::Cgnat, "udp64/new connection each frame (cgnat)"),
            (
                Mode::CgnatFullOthers,
                "udp64/new connection each frame (cgnat, 4096 others in full)",
            ),
            (
                Mode::CgnatNoEim,
                "udp64/new connection each frame (cgnat, EIM off)",
            ),
            (
                Mode::ConntrackOnly,
                "udp64/new connection each frame (conntrack, no NAT)",
            ),
        ] {
            lab.set(mode);
            g.bench_function(name, |b| {
                b.iter_custom(|iters| {
                    (0..iters)
                        .map(|_| {
                            lab.forget_new();
                            lab.new_connections(NEW).0
                        })
                        .sum()
                })
            });
            lab.forget_new();
            let (_, got) = lab.new_connections(NEW);
            eprintln!("{name}: {got} of {NEW} frames forwarded");
        }
        g.finish();
        alternated(&mut lab);
        exhaustion(c, &mut lab);
        lab.hal.apply(&lab.applied, &Config::default()).unwrap();
    }

    /// G2.7, the cost of the exhaustion chain when nobody is out of ports:
    /// the three tables measured in turn, round after round, so a busy
    /// machine weighs on all alike; the median of each.
    fn alternated(lab: &mut Lab) {
        let modes = [
            (Mode::CgnatNoIcmp, "without the chain"),
            (Mode::Cgnat, "chain, set empty"),
            (Mode::CgnatFullOthers, "chain, 4096 others in set"),
        ];
        let mut new: Vec<Vec<f64>> = vec![Vec::new(); modes.len()];
        let mut est: Vec<Vec<f64>> = vec![Vec::new(); modes.len()];
        for _ in 0..9 {
            for (i, (mode, _)) in modes.iter().enumerate() {
                lab.set(*mode);
                lab.forget_new();
                let (t, got) = lab.new_connections(NEW);
                new[i].push(got as f64 / t.as_secs_f64());
                let (t, got) = lab.burst(BURST);
                est[i].push(got as f64 / t.as_secs_f64());
            }
        }
        let median = |v: &mut Vec<f64>| {
            v.sort_by(f64::total_cmp);
            v[v.len() / 2]
        };
        for (i, (_, name)) in modes.iter().enumerate() {
            eprintln!(
                "alternated, {name}: {:.0} new connections/s, {:.0} established pps (medians of 9)",
                median(&mut new[i]),
                median(&mut est[i])
            );
        }
        lab.forget_new();
    }

    /// Frames one exhaustion storm sends.
    const STORM: u64 = 20_000;
    /// Subscribers run out of ports in the exhaustion group.
    const EXHAUSTED: u8 = 8;

    /// Serve the exhaustion queues, one thread each (as the daemon does),
    /// until the flag drops.
    fn serve(
        hal: &mut LinuxHal,
        on: &std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Vec<std::thread::JoinHandle<()>> {
        (0..corerouter_hal::cgnat::EXHAUSTED_QUEUES)
            .map(|i| {
                let mut q = hal.cgnat_exhaustion_queue(i).unwrap();
                let on = on.clone();
                std::thread::Builder::new()
                    .name(format!("cgnat-icmp-{i}"))
                    .spawn(move || {
                        while on.load(std::sync::atomic::Ordering::Relaxed) {
                            q.serve(Duration::from_millis(50)).unwrap();
                        }
                    })
                    .unwrap()
            })
            .collect()
    }

    /// G2.7: subscribers out of ports. The time from a refused frame to its
    /// ICMP back on `fa`, and how many refused frames per second the queue
    /// threads handle in a storm (one subscriber to one destination lands
    /// in one queue: the kernel hashes the addresses; eight spread).
    pub fn exhaustion(c: &mut Criterion, lab: &mut Lab) {
        lab.set(Mode::Exhaust);
        let (fb, fa) = (lab.fb_mac, lab.fa_mac);
        // Each of the first EXHAUSTED subscribers takes its 64 ports to its
        // far end (unanswered UDP, 30 s of conntrack life: enough).
        let fill: Vec<Vec<u8>> = (1..=EXHAUSTED)
            .flat_map(|h| {
                (0..64u16).map(move |k| frame(fb, fa, (subscriber(h), 50_000 + k), far_end(h)))
            })
            .collect();
        let (_, through) = lab.send(fill.len() as u64, |i| fill[i as usize].clone());
        assert_eq!(through, fill.len() as u64, "every slot filled");
        let subs: Vec<Ipv4Addr> = (1..=EXHAUSTED).map(subscriber).collect();
        lab.hal.cgnat_full(&subs).unwrap();
        let on = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let threads = serve(&mut lab.hal, &on);
        // The ICMP comes back to the subscriber through fb, to fa.
        let (fa_link, _) = link("fa");
        let rx = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0x0300))).unwrap();
        bind(rx.as_raw_fd(), &fa_link).unwrap();
        rx.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let rx = std::net::UdpSocket::from(rx);
        let icmp_back = |rx: &std::net::UdpSocket| -> bool {
            let mut b = [0u8; 1600];
            while let Ok(n) = rx.recv(&mut b) {
                // Ethernet, IPv4, protocol ICMP, type 3 code 1.
                if n > 34 && b[12..14] == [8, 0] && b[23] == 1 && b[34] == 3 && b[35] == 1 {
                    return true;
                }
            }
            false
        };
        let mut port = 20_000u16;
        let mut g = c.benchmark_group("netns_cgnat_exhaustion");
        g.sample_size(20);
        g.bench_function("udp64/refused frame to its ICMP", |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    // Another subscriber each time keeps the limiter out of
                    // the way (100/s each).
                    let h = 1 + (port % u16::from(EXHAUSTED)) as u8;
                    port = port.wrapping_add(1).max(20_000);
                    let f = frame(fb, fa, (subscriber(h), port), far_end(h));
                    let start = Instant::now();
                    let _ = send(lab.tx.as_raw_fd(), &f, MsgFlags::empty());
                    assert!(icmp_back(&rx), "the ICMP came back");
                    total += start.elapsed();
                    std::thread::sleep(Duration::from_millis(15));
                }
                total
            })
        });
        let _ = lab.hal.cgnat_exhausted();
        g.sample_size(10);
        g.throughput(Throughput::Elements(STORM));
        for (spread, name) in [
            (1u8, "udp64/storm of refused frames, one subscriber"),
            (
                EXHAUSTED,
                "udp64/storm of refused frames, eight subscribers",
            ),
        ] {
            let mut handled = 0u64;
            g.bench_function(name, |b| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let base = port;
                        port = port.wrapping_add(STORM as u16).max(20_000);
                        let start = Instant::now();
                        let fd = lab.tx.as_raw_fd();
                        for i in 0..STORM {
                            let h = 1 + (i % u64::from(spread)) as u8;
                            let p = base.wrapping_add(i as u16).max(1024);
                            let f = frame(fb, fa, (subscriber(h), p), far_end(h));
                            let _ = send(fd, &f, MsgFlags::empty());
                        }
                        // Until the queues answered all they will.
                        let mut seen = 0;
                        let mut quiet = 0;
                        while seen < STORM && quiet < 20 {
                            std::thread::sleep(Duration::from_millis(2));
                            let (_, st) = lab.hal.cgnat_exhausted();
                            if st.seen == 0 {
                                quiet += 1;
                            } else {
                                quiet = 0;
                            }
                            seen += st.seen;
                        }
                        handled += seen;
                        total += start.elapsed();
                    }
                    total
                })
            });
            eprintln!("{name}: {handled} frames looked at by the queues in all");
        }
        g.finish();
        // The limits held under the storm: count what went out in one.
        let _ = lab.hal.cgnat_exhausted();
        let start = Instant::now();
        let fd = lab.tx.as_raw_fd();
        for i in 0..STORM {
            let f = frame(
                fb,
                fa,
                (subscriber(1), 1024 + (i % 60_000) as u16),
                far_end(1),
            );
            let _ = send(fd, &f, MsgFlags::empty());
        }
        std::thread::sleep(Duration::from_millis(300));
        let (_, st) = lab.hal.cgnat_exhausted();
        let secs = start.elapsed().as_secs_f64();
        eprintln!(
            "storm from one subscriber: {} looked at, {} refused, {} ICMP sent, {} held back by the limiter, in {secs:.2} s",
            st.seen, st.refused, st.icmp, st.limited
        );
        assert!(
            st.icmp as f64 <= 100.0 + 100.0 * secs + 1.0,
            "the per-subscriber limit held"
        );
        on.store(false, std::sync::atomic::Ordering::Relaxed);
        for t in threads {
            t.join().unwrap();
        }
    }
}

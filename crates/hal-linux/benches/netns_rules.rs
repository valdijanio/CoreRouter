//! G1.27e: what `/routing rule` costs in the kernel, in a throwaway network
//! namespace (no root, nothing reaches the host):
//!
//! ```sh
//! COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- \
//!     cargo bench -p corerouter-hal-linux --bench netns_rules
//! ```
//!
//! - `apply/*`: writing N rules through `LinuxHal::apply`, and one rule more
//!   on top of N (all below it move, the worst case);
//! - `forward/*`: frames per second forwarded with N rules that do not match
//!   before `main` (`fib_rules_lookup` walks them per packet); 0 is the
//!   kernel's list untouched;
//! - `output/*`: lookups per second of a socket's `sendto` on 1 and 4 threads
//!   (the walk is under RCU: no lock to share);
//! - `first_rule`: the first rule over a large main table
//!   (`fib4_rule_configure` calls `fib_unmerge` the first time).

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
    if !linux::ready() {
        return;
    }
    // First: only a namespace with no rule yet pays `fib_unmerge`.
    linux::first_rule();
    let mut c = criterion::Criterion::default().configure_from_args();
    linux::apply(&mut c);
    linux::forward(&mut c);
    linux::output(&mut c);
    c.final_summary();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
    use std::os::fd::AsRawFd;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use corerouter_hal::Hal;
    use corerouter_hal_linux::{LinuxHal, Policy};
    use corerouter_model::policy_rule::{RoutingRule, RuleAction};
    use corerouter_model::{Config, ItemId, RoutingTable};
    use criterion::{Criterion, Throughput};
    use nix::ifaddrs::getifaddrs;
    use nix::sys::socket::{LinkAddr, MsgFlags, bind, send};
    use socket2::{Domain, Protocol, Socket, Type};

    const ENV: &str = "COREROUTER_NETNS_BENCH";
    /// Frames per iteration.
    const BURST: u64 = 20_000;
    const COUNTS: [usize; 6] = [0, 1, 10, 100, 1000, 4096];

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
        assert_eq!(names, ["lo"], "{ENV}=1 but this namespace is not fresh");
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

    /// Rule `i`: from a /32 no packet here has.
    fn rule(i: usize) -> RoutingRule {
        let [_, _, a, b] = u32::try_from(i).unwrap().to_be_bytes();
        RoutingRule {
            id: ItemId(u32::try_from(i).unwrap() + 1),
            src_address: Some(format!("10.200.{a}.{b}/32").parse().unwrap()),
            dst_address: None,
            interface: None,
            routing_mark: None,
            action: RuleAction::Lookup,
            table: RoutingTable::Main,
            min_prefix: None,
            disabled: false,
            comment: String::new(),
        }
    }

    fn with_rules(n: usize) -> Config {
        let mut c = Config::default();
        c.routing.rules = (0..n).map(rule).collect();
        c
    }

    pub fn apply(c: &mut Criterion) {
        let mut g = c.benchmark_group("netns_rules_apply");
        g.sample_size(10);
        let mut hal = LinuxHal::new();
        for n in [100usize, 1000, 4096] {
            let to = with_rules(n);
            g.throughput(Throughput::Elements(n as u64));
            g.bench_function(format!("write/{n}"), |b| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let start = Instant::now();
                        hal.apply(&Config::default(), &to).unwrap();
                        total += start.elapsed();
                        hal.apply(&to, &Config::default()).unwrap();
                    }
                    total
                });
            });
            g.bench_function(format!("remove/{n}"), |b| {
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        hal.apply(&Config::default(), &to).unwrap();
                        let start = Instant::now();
                        hal.apply(&to, &Config::default()).unwrap();
                        total += start.elapsed();
                    }
                    total
                });
            });
            // One more at the top: every one below takes a new priority.
            let mut top = to.clone();
            top.routing.rules.insert(0, rule(n + 1));
            g.throughput(Throughput::Elements(1));
            g.bench_function(format!("insert-top/{n}"), |b| {
                hal.apply(&Config::default(), &to).unwrap();
                b.iter_custom(|iters| {
                    let mut total = Duration::ZERO;
                    for _ in 0..iters {
                        let start = Instant::now();
                        hal.apply(&to, &top).unwrap();
                        total += start.elapsed();
                        hal.apply(&top, &to).unwrap();
                    }
                    total
                });
                hal.apply(&to, &Config::default()).unwrap();
            });
            // Nothing changed: the commit of another section.
            g.bench_function(format!("unchanged/{n}"), |b| {
                hal.apply(&Config::default(), &to).unwrap();
                b.iter(|| hal.apply(&to, &to).unwrap());
                hal.apply(&to, &Config::default()).unwrap();
            });
        }
        g.finish();
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

    fn frame(dst_mac: [u8; 6], src_mac: [u8; 6], host: u8) -> Vec<u8> {
        let mut f = Vec::with_capacity(64);
        f.extend_from_slice(&dst_mac);
        f.extend_from_slice(&src_mac);
        f.extend_from_slice(&[0x08, 0x00]);
        let mut iph = vec![
            0x45, 0, 0, 50, 0, 0, 0x40, 0, 64, 17, 0, 0, 10, 201, 0, 2, 198, 18, 0, host,
        ];
        let c = checksum(&iph);
        iph[10..12].copy_from_slice(&c.to_be_bytes());
        f.extend_from_slice(&iph);
        f.extend_from_slice(&40000u16.to_be_bytes());
        f.extend_from_slice(&(9000u16 + u16::from(host)).to_be_bytes());
        f.extend_from_slice(&30u16.to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.resize(64, 0);
        f
    }

    pub fn forward(c: &mut Criterion) {
        ip(&["link", "add", "ra", "type", "veth", "peer", "name", "rb"]);
        ip(&["link", "add", "ro", "type", "dummy"]);
        for d in ["ra", "rb", "ro"] {
            ip(&["link", "set", d, "up"]);
        }
        ip(&["addr", "add", "10.201.0.1/24", "dev", "rb"]);
        ip(&["addr", "add", "10.202.0.1/24", "dev", "ro"]);
        ip(&["route", "add", "198.18.0.0/15", "dev", "ro"]);
        std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
        std::fs::write("/proc/sys/net/ipv4/conf/all/rp_filter", "0").unwrap();
        let (ra, ra_mac) = link("ra");
        let (_, rb_mac) = link("rb");
        let sock = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0))).unwrap();
        bind(sock.as_raw_fd(), &ra).unwrap();
        let frames: Vec<Vec<u8>> = (0..=255u8).map(|h| frame(rb_mac, ra_mac, h)).collect();
        let mut hal = LinuxHal::with_policy(Policy {
            manage: vec!["ra".into(), "rb".into(), "ro".into()],
            unmanaged: Vec::new(),
        });
        let tx = |hal: &mut LinuxHal| {
            hal.poll()
                .into_iter()
                .find(|l| l.name.as_str() == "ro")
                .map_or(0, |l| l.tx_packets)
        };
        let mut burst = |hal: &mut LinuxHal| {
            let before = tx(hal);
            let start = Instant::now();
            for i in 0..BURST {
                let _ = send(sock.as_raw_fd(), &frames[(i % 256) as usize], MsgFlags::empty());
            }
            let mut last = tx(hal);
            loop {
                std::thread::sleep(Duration::from_micros(200));
                let now = tx(hal);
                if now == last || now - before >= BURST {
                    break;
                }
                last = now;
            }
            (start.elapsed(), tx(hal) - before)
        };
        let mut g = c.benchmark_group("netns_rules_forward");
        g.throughput(Throughput::Elements(BURST));
        g.sample_size(20);
        let mut applied = Config::default();
        for n in COUNTS {
            let to = with_rules(n);
            hal.apply(&applied, &to).unwrap();
            applied = to;
            g.bench_function(format!("udp64/{n}"), |b| {
                b.iter_custom(|iters| (0..iters).map(|_| burst(&mut hal).0).sum());
            });
            let (_, got) = burst(&mut hal);
            eprintln!("{n} rules: {got} of {BURST} frames forwarded");
        }
        // The same 4096 sources as one address list and one mark: a hash
        // lookup in the mangle and a single rule in the walk.
        let mut to = Config::default();
        for i in 0..4095u32 {
            let [_, _, a, b] = i.to_be_bytes();
            let entry = serde_json::json!({
                "id": format!("*{:X}", i + 1), "list": "many", "address": format!("10.200.{a}.{b}/32"),
            });
            to.ip.firewall.address_lists.push(serde_json::from_value(entry).unwrap());
        }
        to.ip.firewall.address_lists.push(
            serde_json::from_value(serde_json::json!({
                "id": "*FFFF", "list": "many", "address": "10.201.0.2/32",
            }))
            .unwrap(),
        );
        to.ip.firewall.mangle.push(
            serde_json::from_value(serde_json::json!({
                "id": "*1", "chain": "prerouting",
                "matchers": {"src_address_list": "many"},
                "action": {"type": "mark-routing", "new_routing_mark": "main"},
            }))
            .unwrap(),
        );
        hal.apply(&applied, &to).unwrap();
        applied = to;
        g.bench_function("udp64/mark-from-a-list-of-4096", |b| {
            b.iter_custom(|iters| (0..iters).map(|_| burst(&mut hal).0).sum());
        });
        let (_, got) = burst(&mut hal);
        eprintln!("list: {got} of {BURST} frames forwarded");
        g.finish();
        hal.apply(&applied, &Config::default()).unwrap();
        ip(&["link", "del", "ra"]);
    }

    pub fn output(c: &mut Criterion) {
        ip(&["link", "add", "rq", "type", "dummy"]);
        ip(&["link", "set", "rq", "up"]);
        ip(&["addr", "add", "10.203.0.1/24", "dev", "rq"]);
        ip(&["route", "add", "198.20.0.0/15", "dev", "rq"]);
        // Each `sendto` on an unconnected socket looks the route up.
        const SENDS: u64 = 50_000;
        let run = |threads: u64| {
            let start = Instant::now();
            std::thread::scope(|scope| {
                for _ in 0..threads {
                    scope.spawn(|| {
                        let s = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
                        let to = SocketAddr::from((Ipv4Addr::new(198, 20, 0, 9), 9));
                        for _ in 0..SENDS {
                            let _ = s.send_to(&[0; 8], to);
                        }
                    });
                }
            });
            start.elapsed()
        };
        let mut g = c.benchmark_group("netns_rules_output");
        g.sample_size(10);
        let mut hal = LinuxHal::new();
        let mut applied = Config::default();
        for n in [0usize, 100, 1000, 4096] {
            let to = with_rules(n);
            hal.apply(&applied, &to).unwrap();
            applied = to;
            for threads in [1u64, 4] {
                g.throughput(Throughput::Elements(threads * SENDS));
                g.bench_function(format!("{n}/threads-{threads}"), |b| {
                    b.iter_custom(|iters| (0..iters).map(|_| run(threads)).sum());
                });
            }
        }
        g.finish();
        hal.apply(&applied, &Config::default()).unwrap();
        ip(&["link", "del", "rq"]);
    }

    /// `first_rule`: printed, not a criterion sample (it only happens once
    /// per boot of the namespace's tables).
    pub fn first_rule() {
        let batch = std::env::temp_dir().join("cr-netns-rules-routes.txt");
        ip(&["link", "add", "rf", "type", "dummy"]);
        ip(&["link", "set", "rf", "up"]);
        let mut text = String::new();
        const ROUTES: u32 = 200_000;
        for i in 0..ROUTES {
            let [_, a, b, c] = i.to_be_bytes();
            text.push_str(&format!("route add 100.{a}.{b}.{c}/32 dev rf\n"));
        }
        std::fs::write(&batch, text).unwrap();
        ip(&["-batch", batch.to_str().unwrap()]);
        let mut hal = LinuxHal::new();
        let start = Instant::now();
        let to = with_rules(1);
        hal.apply(&Config::default(), &to).unwrap();
        eprintln!(
            "first rule of the namespace over {ROUTES} routes in main: {:?}",
            start.elapsed()
        );
        hal.apply(&to, &Config::default()).unwrap();
        ip(&["link", "del", "rf"]);
        let _ = std::fs::remove_file(batch);
    }
}

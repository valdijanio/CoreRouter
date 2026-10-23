//! Host ICMP (`icmp.rs`) against a real kernel, inside a throwaway network
//! namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_icmp
//! ```
//!
//! Same guard as `tests/netns.rs`. Both socket kinds are exercised: raw
//! (root of the user namespace has `CAP_NET_RAW` there) and ping sockets
//! (`net.ipv4.ping_group_range` is per namespace, so the test opens it).
//! The far side of a cable and a router in between are nested namespaces
//! (`unshare --net sleep`, owned by the same user namespace, reached with
//! `nsenter`):
//!
//! ```text
//!   this ns  a0 ──veth── b0  [router ns]  b1 ──veth (mtu 1400)── c0  [host ns]
//!   10.9.N.1/24     10.9.N.2/24       10.10.N.1/24          10.10.N.2/24
//!   fd09:N::1/64    fd09:N::2/64      fd0a:N::1/64          fd0a:N::2/64
//! ```
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::net::IpAddr;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use corerouter_hal::probe::{
    Probe, ProbeError, ProbeProto, ProbeSocket, Prober, Reply, ReplyKind, SocketOptions,
};
use corerouter_hal_linux::icmp::{HostProber, Kind};

const ENV: &str = "COREROUTER_NETNS_TESTS";

fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!(
            "skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net` \
             (cargo xtask netns)"
        );
        return false;
    }
    static FRESH: OnceLock<Result<(), String>> = OnceLock::new();
    let fresh = FRESH.get_or_init(|| {
        let out = Command::new("ip")
            .args(["-o", "link", "show"])
            .output()
            .map_err(|e| format!("cannot run `ip`: {e}"))?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let names: Vec<&str> = text
            .lines()
            .filter_map(|l| l.split(':').nth(1))
            .map(str::trim)
            .collect();
        if names != ["lo"] {
            return Err(format!(
                "{ENV}=1 but this network namespace has {names:?}, not just lo; refusing to \
                 touch it (run inside `unshare --user --map-root-user --net`)"
            ));
        }
        ip(&["link", "set", "lo", "up"]);
        // Only gid 0 is mapped in this user namespace.
        std::fs::write("/proc/sys/net/ipv4/ping_group_range", "0 0")
            .map_err(|e| format!("cannot open ping sockets in this namespace: {e}"))?;
        Ok(())
    });
    if let Err(e) = fresh {
        panic!("{e}");
    }
    true
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{cmd:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn ip(args: &[&str]) -> String {
    run(Command::new("ip").args(args))
}

/// A nested network namespace, alive while this value is.
struct Ns(Child);

impl Ns {
    fn new() -> Self {
        let child = Command::new("unshare")
            .args(["--net", "--", "sleep", "600"])
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let ns = Ns(child);
        // Wait until the child is in its own namespace.
        let mine = std::fs::read_link("/proc/self/ns/net").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while std::fs::read_link(format!("/proc/{}/ns/net", ns.pid())).ok() == Some(mine.clone()) {
            assert!(Instant::now() < deadline, "unshare --net did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
        ns.ip(&["link", "set", "lo", "up"]);
        ns
    }

    fn pid(&self) -> String {
        self.0.id().to_string()
    }

    fn ip(&self, args: &[&str]) -> String {
        let pid = self.pid();
        run(Command::new("nsenter")
            .args(["-t", pid.as_str(), "-n", "ip"])
            .args(args))
    }

    fn sysctl(&self, path: &str, value: &str) {
        let pid = self.pid();
        let script = format!("echo {value} > /proc/sys/{path}");
        run(Command::new("nsenter").args(["-t", pid.as_str(), "-n", "sh", "-c", script.as_str()]));
    }
}

impl Drop for Ns {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// The topology of the module docs, numbered `n` so tests run side by side.
struct Lab {
    _router: Ns,
    _host: Ns,
    near: String,
    far: String,
    near6: String,
    far6: String,
    link: String,
}

fn lab(n: u8) -> Lab {
    let router = Ns::new();
    let host = Ns::new();
    let (a0, b0, b1, c0) = (
        format!("a{n}"),
        format!("b{n}"),
        format!("r{n}"),
        format!("c{n}"),
    );
    ip(&[
        "link",
        "add",
        &a0,
        "type",
        "veth",
        "peer",
        "name",
        &b0,
        "netns",
        &router.pid(),
    ]);
    router.ip(&[
        "link",
        "add",
        &b1,
        "type",
        "veth",
        "peer",
        "name",
        &c0,
        "netns",
        &host.pid(),
    ]);
    router.sysctl("net/ipv4/ip_forward", "1");
    router.sysctl("net/ipv6/conf/all/forwarding", "1");
    let (v4a, v4b) = (format!("10.9.{n}"), format!("10.10.{n}"));
    let (v6a, v6b) = (format!("fd09:{n}:"), format!("fd0a:{n}:"));
    ip(&["addr", "add", &format!("{v4a}.1/24"), "dev", &a0]);
    ip(&["addr", "add", &format!("{v6a}:1/64"), "dev", &a0, "nodad"]);
    ip(&["link", "set", &a0, "up"]);
    ip(&[
        "route",
        "add",
        &format!("{v4b}.0/24"),
        "via",
        &format!("{v4a}.2"),
    ]);
    ip(&[
        "route",
        "add",
        &format!("{v6b}:/64"),
        "via",
        &format!("{v6a}:2"),
    ]);
    router.ip(&["addr", "add", &format!("{v4a}.2/24"), "dev", &b0]);
    router.ip(&["addr", "add", &format!("{v6a}:2/64"), "dev", &b0, "nodad"]);
    router.ip(&["addr", "add", &format!("{v4b}.1/24"), "dev", &b1]);
    router.ip(&["addr", "add", &format!("{v6b}:1/64"), "dev", &b1, "nodad"]);
    router.ip(&["link", "set", &b1, "mtu", "1400"]);
    router.ip(&["link", "set", &b0, "up"]);
    router.ip(&["link", "set", &b1, "up"]);
    host.ip(&["addr", "add", &format!("{v4b}.2/24"), "dev", &c0]);
    host.ip(&["addr", "add", &format!("{v6b}:2/64"), "dev", &c0, "nodad"]);
    host.ip(&["link", "set", &c0, "mtu", "1400"]);
    host.ip(&["link", "set", &c0, "up"]);
    host.ip(&["route", "add", "default", "via", &format!("{v4b}.1")]);
    host.ip(&["route", "add", "default", "via", &format!("{v6b}:1")]);
    Lab {
        _router: router,
        _host: host,
        near: format!("{v4a}.2"),
        far: format!("{v4b}.2"),
        near6: format!("{v6a}:2"),
        far6: format!("{v6b}:2"),
        link: a0,
    }
}

/// Send one probe, wait up to 2 s for its answer.
fn ask(
    sock: &mut dyn ProbeSocket,
    dst: &str,
    seq: u16,
    ttl: Option<u8>,
    size: u16,
) -> Option<Reply> {
    let probe = Probe {
        dst: dst.parse().unwrap(),
        seq,
        ttl,
        size,
    };
    sock.send(&probe).unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if let Some(r) = sock.recv(Duration::from_millis(200)).unwrap()
            && r.seq == seq
        {
            return Some(r);
        }
    }
    None
}

/// Retry while neighbor discovery / ARP settle (the first probe of a fresh
/// link can be lost).
fn ask_retry(sock: &mut dyn ProbeSocket, dst: &str, seq: u16, ttl: Option<u8>, size: u16) -> Reply {
    for i in 0..5 {
        if let Some(r) = ask(sock, dst, seq.wrapping_add(i * 1000), ttl, size) {
            return r;
        }
    }
    panic!("no answer from {dst}");
}

/// Like `ask_retry`, but also retries a non-echo answer: right after the lab
/// comes up, the first IPv6 probe can come back "unreachable" while the
/// router still resolves the far host (seen in CI). Returns the last answer.
fn ask_echo(sock: &mut dyn ProbeSocket, dst: &str, seq: u16, ttl: Option<u8>, size: u16) -> Reply {
    let mut last = ask_retry(sock, dst, seq, ttl, size);
    for i in 1..10 {
        if last.kind == ReplyKind::Echo {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
        last = ask_retry(sock, dst, seq.wrapping_add(i * 100), ttl, size);
    }
    last
}

fn ip_of(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn loopback_with_both_socket_kinds() {
    if !in_netns() {
        return;
    }
    assert!(HostProber::detect().is_ok());
    for kind in [Kind::Ping, Kind::Raw] {
        let prober = HostProber::with_kind(kind);
        let mut sock = prober.open(&SocketOptions::default()).unwrap();
        for (i, dst) in ["127.0.0.1", "::1"].into_iter().enumerate() {
            let r = ask_echo(sock.as_mut(), dst, 10 + i as u16, None, 84);
            assert_eq!(r.kind, ReplyKind::Echo, "{kind:?} {dst}");
            assert_eq!(r.from, ip_of(dst));
            assert!(r.rtt < Duration::from_millis(500));
            assert_eq!(r.ttl, Some(64), "{kind:?} {dst}");
            assert_eq!(r.size, Some(84), "{kind:?} {dst}");
        }
    }
}

#[test]
fn across_a_veth_and_through_a_router() {
    if !in_netns() {
        return;
    }
    let lab = lab(1);
    for kind in [Kind::Ping, Kind::Raw] {
        let prober = HostProber::with_kind(kind);
        let mut sock = prober.open(&SocketOptions::default()).unwrap();
        // The other side of the cable.
        let r = ask_retry(sock.as_mut(), &lab.near, 1, None, 56);
        assert_eq!(
            (r.kind.clone(), r.ttl),
            (ReplyKind::Echo, Some(64)),
            "{kind:?}"
        );
        let r = ask_echo(sock.as_mut(), &lab.near6, 2, None, 56);
        assert_eq!(r.kind, ReplyKind::Echo, "{kind:?}");
        // One router further: TTL 63, and TTL 1 dies at the router.
        let r = ask_retry(sock.as_mut(), &lab.far, 3, None, 56);
        assert_eq!(
            (r.kind.clone(), r.ttl),
            (ReplyKind::Echo, Some(63)),
            "{kind:?}"
        );
        let r = ask_retry(sock.as_mut(), &lab.far, 4, Some(1), 56);
        assert_eq!(r.kind, ReplyKind::TtlExceeded, "{kind:?}");
        assert_eq!(r.from, ip_of(&lab.near));
        // TTL 2 is enough to reach the host behind the router (what MTR walks).
        let r = ask_echo(sock.as_mut(), &lab.far, 9, Some(2), 56);
        assert_eq!(r.kind, ReplyKind::Echo, "{kind:?}");
        assert_eq!(r.from, ip_of(&lab.far));
        let r = ask_retry(sock.as_mut(), &lab.far6, 5, Some(1), 56);
        assert_eq!(r.kind, ReplyKind::TtlExceeded, "{kind:?}");
        assert_eq!(r.from, ip_of(&lab.near6));
        // Hosts unreachable behind the router: no neighbor answers.
        let r = ask(sock.as_mut(), "10.10.1.77", 6, None, 56);
        if let Some(r) = r {
            assert!(
                matches!(r.kind, ReplyKind::Unreachable(_)),
                "{kind:?} {r:?}"
            );
        }
    }
}

#[test]
fn dont_fragment_finds_the_narrow_link() {
    if !in_netns() {
        return;
    }
    let lab = lab(2);
    for kind in [Kind::Ping, Kind::Raw] {
        let prober = HostProber::with_kind(kind);
        let df = SocketOptions {
            dont_fragment: true,
            ..SocketOptions::default()
        };
        let mut sock = prober.open(&df).unwrap();
        let r = ask_echo(sock.as_mut(), &lab.far, 1, None, 1400);
        assert_eq!(r.kind, ReplyKind::Echo, "{kind:?}");
        // 1401 bytes with DF: the router says "fragmentation needed, 1400"
        // the first time; after that the kernel knows the path MTU and
        // refuses locally.
        let mut said = None;
        for seq in 2..6 {
            let probe = Probe {
                dst: ip_of(&lab.far),
                seq,
                ttl: None,
                size: 1401,
            };
            match sock.send(&probe) {
                Err(ProbeError::TooBig(_)) => {
                    said.get_or_insert(ReplyKind::TooBig { mtu: None });
                }
                Err(e) => panic!("{kind:?}: {e}"),
                Ok(()) => {
                    if let Some(r) = sock.recv(Duration::from_secs(1)).unwrap() {
                        assert_eq!(r.from, ip_of(&lab.near), "{kind:?}");
                        said = Some(r.kind);
                        break;
                    }
                }
            }
        }
        match said {
            Some(ReplyKind::TooBig { mtu }) => {
                assert!(mtu.is_none_or(|m| m == 1400), "{kind:?} {mtu:?}");
            }
            other => panic!("{kind:?}: expected too big, got {other:?}"),
        }
        // IPv6: "packet too big" from the router.
        let r = ask_echo(sock.as_mut(), &lab.far6, 7, None, 1400);
        assert_eq!(r.kind, ReplyKind::Echo, "{kind:?}");
        let probe = Probe {
            dst: ip_of(&lab.far6),
            seq: 8,
            ttl: None,
            size: 1401,
        };
        match sock.send(&probe) {
            Err(ProbeError::TooBig(_)) => {}
            Err(e) => panic!("{kind:?}: {e}"),
            Ok(()) => {
                if let Some(r) = sock.recv(Duration::from_secs(1)).unwrap() {
                    assert!(matches!(r.kind, ReplyKind::TooBig { .. }), "{kind:?} {r:?}");
                }
            }
        }
    }
    // A smaller local link: refused before it leaves.
    ip(&["link", "set", &lab.link, "mtu", "1300"]);
    let prober = HostProber::with_kind(Kind::Raw);
    let mut sock = prober
        .open(&SocketOptions {
            dont_fragment: true,
            ..SocketOptions::default()
        })
        .unwrap();
    let probe = Probe {
        dst: ip_of(&lab.near),
        seq: 1,
        ttl: None,
        size: 1301,
    };
    assert!(matches!(sock.send(&probe), Err(ProbeError::TooBig(_))));
}

#[test]
fn source_address_and_device_are_honored() {
    if !in_netns() {
        return;
    }
    let lab = lab(3);
    let prober = HostProber::with_kind(Kind::Raw);
    let mut sock = prober
        .open(&SocketOptions {
            device: Some(lab.link.clone()),
            src: Some(ip_of("10.9.3.1")),
            ..SocketOptions::default()
        })
        .unwrap();
    let r = ask_echo(sock.as_mut(), &lab.far, 1, None, 56);
    assert_eq!(r.kind, ReplyKind::Echo);
    // A source that is not ours cannot be bound.
    let mut bad = prober
        .open(&SocketOptions {
            src: Some(ip_of("192.0.2.1")),
            ..SocketOptions::default()
        })
        .unwrap();
    let probe = Probe {
        dst: ip_of(&lab.near),
        seq: 1,
        ttl: None,
        size: 56,
    };
    assert!(matches!(bad.send(&probe), Err(ProbeError::Unavailable(_))));
}

/// G6.4c: UDP and TCP SYN probes (no raw socket), classic and Paris, walk
/// the path: the router answers "time exceeded", the host "port
/// unreachable" (UDP), RST (TCP, nothing listening) or SYN-ACK (TCP, a
/// listener).
#[test]
fn udp_and_tcp_probes_walk_the_path() {
    if !in_netns() {
        return;
    }
    let lab = lab(4);
    // A listener on the far host, port 8080, both families.
    let pid = lab._host.pid();
    let mut listener = Command::new("nsenter")
        .args(["-t", pid.as_str(), "-n", "python3", "-c",
            "import socket,time\ns=socket.socket(socket.AF_INET6)\ns.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,0)\ns.bind(('::',8080))\ns.listen(64)\ntime.sleep(60)"])
        .stdin(Stdio::null())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let prober = HostProber::with_kind(Kind::Ping);
    // Neighbor discovery on the fresh links takes a second once: not the
    // probes' RTT.
    let mut warm = prober.open(&SocketOptions::default()).unwrap();
    for far in [&lab.far, &lab.far6] {
        ask_retry(warm.as_mut(), far, 1, None, 64);
    }
    let cases = [
        (ProbeProto::Udp { port: 33434 }, "port unreachable"),
        (ProbeProto::Tcp { port: 9 }, "rst"),
        (ProbeProto::Tcp { port: 8080 }, "syn-ack"),
    ];
    for (proto, end) in cases {
        for paris in [false, true] {
            for (near, far) in [(&lab.near, &lab.far), (&lab.near6, &lab.far6)] {
                let mut sock = prober
                    .open(&SocketOptions {
                        proto,
                        paris,
                        ..SocketOptions::default()
                    })
                    .unwrap();
                let r = ask_retry(sock.as_mut(), far, 10, Some(1), 64);
                assert_eq!(
                    r.kind,
                    ReplyKind::TtlExceeded,
                    "{proto:?} paris={paris} {far}"
                );
                assert_eq!(r.from.to_string(), *near);
                let r = ask_retry(sock.as_mut(), far, 20, Some(8), 64);
                assert_eq!(
                    r.kind,
                    ReplyKind::Reached(end.into()),
                    "{proto:?} paris={paris} {far}"
                );
                assert_eq!(r.from.to_string(), *far);
                assert!(
                    r.rtt < Duration::from_secs(1),
                    "{proto:?} paris={paris} {far}: {:?}",
                    r.rtt
                );
            }
        }
    }
    let _ = listener.kill();
    let _ = listener.wait();
}

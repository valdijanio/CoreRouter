//! G4.10e: subscriber notices end to end — a `--backend linux` daemon, its
//! portal, and clients that make each OS's captive-portal probe, directly
//! and behind a customer router (NAT), inside throwaway network namespaces,
//! no root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_notice -- --test-threads 1
//! ```
//!
//! ```text
//!  [sub] 100.64.0.10 ── acc0 100.64.0.1 ┐
//!                                       ├ daemon (this ns) ── up0 198.51.100.1 ── [inet] 198.51.100.7/.8
//!  [lan] 192.168.1.10 ── [cpe] NAT ── cpe1 100.64.1.1 (CPE WAN 100.64.1.10)        HTTP 80 → 204, TCP 443, UDP 53 echo
//! ```
//!
//! Block, notice and throttle; each OS probe (the model's table) gets the
//! portal's redirect, HTTPS is refused at once, DNS passes, the page is
//! served and logged, release takes effect on the next request, and the
//! same with 100 000 subscribers in the list (times printed).
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::process::Stdio;
use std::time::{Duration, Instant};

use common::*;
use corerouter_model::subscriber_notice::probes::PROBES;
use serde_json::{Value, json};

fn daemon(dir: &std::path::Path) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join("g410-notice.log")).unwrap();
    let mut c = in_ns(None, DAEMON);
    c.args([
        "--backend",
        "linux",
        "--no-discovery",
        "--manage",
        "acc0,cpe1,up0",
        "--control",
        "7979",
        "--config-dir",
    ])
    .arg(dir)
    .arg("--token-file")
    .arg(token_file(None, dir))
    .env("RUST_LOG", "info")
    .stdout(Stdio::null())
    .stderr(log);
    let k = Kill(c.spawn().unwrap());
    wait_for("the daemon", || {
        call(None, "interface.list", json!({})).is_ok()
    });
    k
}

fn ok(command: &str, params: Value) -> Value {
    call(None, command, params).unwrap_or_else(|e| panic!("{command}: {e}"))
}

fn batch(steps: Vec<Value>) {
    let mut c = client(CONTROL, token_of(None)).unwrap();
    c.call("engine.batch", json!({"steps": steps, "atomic": true}))
        .unwrap();
}

/// Run `f` on a thread inside the network namespace of `pid`.
fn within<T: Send + 'static>(pid: u32, f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::spawn(move || {
        let ns = std::fs::File::open(format!("/proc/{pid}/ns/net")).unwrap();
        nix::sched::setns(ns, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        f()
    })
    .join()
    .unwrap()
}

/// The "internet": every HTTP request gets 204 (the real probe servers'
/// "internet ok"), 443 accepts, UDP 53 echoes. Sockets made inside `pid`,
/// served from threads here.
fn internet(pid: u32) {
    let (http, tls, dns) = within(pid, || {
        (
            TcpListener::bind("0.0.0.0:80").unwrap(),
            TcpListener::bind("0.0.0.0:443").unwrap(),
            UdpSocket::bind("0.0.0.0:53").unwrap(),
        )
    });
    std::thread::spawn(move || {
        for c in http.incoming().flatten() {
            let mut c = c;
            let _ = c.set_read_timeout(Some(Duration::from_secs(1)));
            let mut buf = [0u8; 2048];
            let _ = c.read(&mut buf);
            let _ = c.write_all(
                b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    std::thread::spawn(move || {
        for c in tls.incoming().flatten() {
            drop(c)
        }
    });
    std::thread::spawn(move || {
        let mut buf = [0u8; 512];
        while let Ok((n, from)) = dns.recv_from(&mut buf) {
            let _ = dns.send_to(&buf[..n], from);
        }
    });
}

#[derive(Debug, PartialEq)]
enum Got {
    /// Status and Location.
    Http(u16, String),
    Refused,
    TimedOut,
}

/// A GET from inside `pid` to `dst` with `host`, as an OS probe makes it.
fn get(pid: u32, dst: &str, host: &str, path: &str) -> (Got, Duration) {
    let dst: SocketAddr = dst.parse().unwrap();
    let (host, path) = (host.to_owned(), path.to_owned());
    within(pid, move || {
        let start = Instant::now();
        let mut s = match TcpStream::connect_timeout(&dst, Duration::from_millis(1500)) {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                return (Got::Refused, start.elapsed());
            }
            Err(_) => return (Got::TimedOut, start.elapsed()),
        };
        let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = write!(
            s,
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: probe-test\r\nConnection: close\r\n\r\n"
        );
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out);
        let text = String::from_utf8_lossy(&out).into_owned();
        let status = text
            .split(' ')
            .nth(1)
            .and_then(|c| c.parse().ok())
            .unwrap_or(0);
        let location = text
            .lines()
            .find_map(|l| l.strip_prefix("Location: "))
            .unwrap_or_default()
            .trim()
            .to_owned();
        (Got::Http(status, location), start.elapsed())
    })
}

fn connect(pid: u32, dst: &str) -> (Got, Duration) {
    let dst: SocketAddr = dst.parse().unwrap();
    within(pid, move || {
        let start = Instant::now();
        let got = match TcpStream::connect_timeout(&dst, Duration::from_millis(1500)) {
            Ok(_) => Got::Http(0, String::new()),
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Got::Refused,
            Err(_) => Got::TimedOut,
        };
        (got, start.elapsed())
    })
}

fn dns_passes(pid: u32) -> bool {
    within(pid, || {
        let s = UdpSocket::bind("0.0.0.0:0").unwrap();
        s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        s.send_to(b"query", "198.51.100.7:53").unwrap();
        let mut buf = [0u8; 16];
        s.recv_from(&mut buf).is_ok()
    })
}

fn probe_path(p: &corerouter_model::subscriber_notice::probes::Probe) -> &'static str {
    if p.path == "*" {
        "/hotspot-detect.html"
    } else {
        p.path
    }
}

/// Every OS probe from `pid`: the portal's 302 to `portal`.
fn every_probe_redirected(pid: u32, portal: &str) {
    for p in PROBES {
        let (got, took) = get(pid, "198.51.100.7:80", p.host, probe_path(p));
        let want = format!("http://{portal}:8880/?via={}", p.os);
        assert_eq!(got, Got::Http(302, want), "{} {}", p.host, p.path);
        assert!(took < Duration::from_secs(1), "{}: {took:?}", p.host);
    }
}

#[test]
fn notices_reach_every_os_directly_and_behind_a_cpe() {
    if !in_netns() {
        return;
    }
    let (sub, cpe, lan, inet) = (namespace_b(), namespace_b(), namespace_b(), namespace_b());
    let (sub_p, cpe_p, lan_p, inet_p) = (sub.0.id(), cpe.0.id(), lan.0.id(), inet.0.id());
    ip(None, &["link", "set", "lo", "up"]);
    ip(
        None,
        &[
            "link",
            "add",
            "acc0",
            "type",
            "veth",
            "peer",
            "name",
            "s0",
            "netns",
            &sub_p.to_string(),
        ],
    );
    ip(
        None,
        &[
            "link",
            "add",
            "cpe1",
            "type",
            "veth",
            "peer",
            "name",
            "w0",
            "netns",
            &cpe_p.to_string(),
        ],
    );
    ip(
        None,
        &[
            "link",
            "add",
            "up0",
            "type",
            "veth",
            "peer",
            "name",
            "i0",
            "netns",
            &inet_p.to_string(),
        ],
    );
    ip(
        Some(cpe_p),
        &[
            "link",
            "add",
            "l0",
            "type",
            "veth",
            "peer",
            "name",
            "c0",
            "netns",
            &lan_p.to_string(),
        ],
    );
    for d in ["acc0", "cpe1", "up0"] {
        ip(None, &["link", "set", d, "up"]);
    }
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
    for (pid, dev, addr, gw) in [
        (sub_p, "s0", "100.64.0.10/24", "100.64.0.1"),
        (cpe_p, "w0", "100.64.1.10/24", "100.64.1.1"),
        (lan_p, "c0", "192.168.1.10/24", "192.168.1.1"),
        (inet_p, "i0", "198.51.100.7/24", ""),
    ] {
        ip(Some(pid), &["link", "set", "lo", "up"]);
        ip(Some(pid), &["addr", "add", addr, "dev", dev]);
        ip(Some(pid), &["link", "set", dev, "up"]);
        if !gw.is_empty() {
            ip(Some(pid), &["route", "add", "default", "via", gw]);
        }
    }
    ip(
        Some(inet_p),
        &["addr", "add", "198.51.100.8/24", "dev", "i0"],
    );
    ip(
        Some(inet_p),
        &["route", "add", "100.64.0.0/16", "via", "198.51.100.1"],
    );
    ip(Some(cpe_p), &["addr", "add", "192.168.1.1/24", "dev", "l0"]);
    ip(Some(cpe_p), &["link", "set", "l0", "up"]);
    let fwd = in_ns(Some(cpe_p), "sh")
        .args(["-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"])
        .status()
        .unwrap();
    assert!(fwd.success());
    // The customer's router: NAT, as every CPE does.
    let nat = in_ns(Some(cpe_p), "nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .and_then(|mut c| {
            c.stdin.take().unwrap().write_all(b"table ip cpe {\n chain post {\n  type nat hook postrouting priority srcnat;\n  oifname \"w0\" masquerade\n }\n}\n")?;
            c.wait()
        })
        .unwrap();
    assert!(nat.success(), "nft in the CPE");
    internet(inet_p);

    let dir = std::env::temp_dir().join(format!("g410-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let _d = daemon(&dir);
    for (a, i) in [
        ("100.64.0.1/24", "acc0"),
        ("100.64.1.1/24", "cpe1"),
        ("198.51.100.1/24", "up0"),
    ] {
        ok("ip.address.add", json!({"address": a, "interface": i}));
    }
    ok(
        "ip.subscriber-notice.profile.add",
        json!({"name": "atraso", "mode": "block", "address_list": "bloqueados", "kill_connections": false}),
    );
    wait_for("the portal", || {
        TcpStream::connect("127.0.0.1:8880").is_ok()
    });

    // Not in the list: the real internet answers.
    assert_eq!(
        get(
            sub_p,
            "198.51.100.7:80",
            "connectivitycheck.gstatic.com",
            "/generate_204"
        )
        .0,
        Got::Http(204, String::new())
    );
    assert_eq!(
        connect(sub_p, "198.51.100.7:443").0,
        Got::Http(0, String::new())
    );

    // In the list (the subscriber, and the CPE's WAN address).
    ok(
        "ip.firewall.address-list.add",
        json!({"list": "bloqueados", "address": "100.64.0.10"}),
    );
    ok(
        "ip.firewall.address-list.add",
        json!({"list": "bloqueados", "address": "100.64.1.10"}),
    );
    wait_for("the portal's snapshot", || {
        matches!(
            get(sub_p, "198.51.100.7:80", "captive.apple.com", "/").0,
            Got::Http(302, _)
        )
    });
    every_probe_redirected(sub_p, "100.64.0.1");
    // Behind the CPE: the phone on the customer's Wi-Fi makes its own probe.
    every_probe_redirected(lan_p, "100.64.1.1");
    // HTTPS refused at once; DNS passes.
    let (got, took) = connect(sub_p, "198.51.100.7:443");
    assert_eq!(got, Got::Refused);
    assert!(
        took < Duration::from_millis(200),
        "refused at once: {took:?}"
    );
    assert_eq!(connect(lan_p, "198.51.100.8:443").0, Got::Refused);
    assert!(dns_passes(sub_p), "DNS passes in block mode");
    // Any plain-HTTP site: 511 with the page.
    assert!(matches!(
        get(sub_p, "198.51.100.8:80", "example.com", "/").0,
        Got::Http(511, _)
    ));
    // The page the OS opens, logged with the probe that brought it.
    ok(
        "ip.subscriber-notice.vars.set",
        json!({"address": "100.64.0.10", "vars": {"valor": "R$ 99,90"}}),
    );
    assert_eq!(
        get(sub_p, "100.64.0.1:8880", "100.64.0.1", "/?via=android").0,
        Got::Http(200, String::new())
    );
    let log = ok(
        "ip.subscriber-notice.log",
        json!({"address": "100.64.0.10"}),
    );
    assert_eq!(log[0]["via"], "android", "{log}");

    // Release: out of the list, the next request goes out.
    let start = Instant::now();
    let id = ok(
        "ip.firewall.address-list.list",
        json!({"list": "bloqueados"}),
    )
    .as_array()
    .unwrap()
    .iter()
    .find(|r| r["address"] == "100.64.0.10")
    .unwrap()["id"]
        .clone();
    ok("ip.firewall.address-list.remove", json!({"id": id}));
    let released = start.elapsed();
    assert_eq!(
        get(
            sub_p,
            "198.51.100.7:80",
            "connectivitycheck.gstatic.com",
            "/generate_204"
        )
        .0,
        Got::Http(204, String::new())
    );
    assert_eq!(
        connect(sub_p, "198.51.100.7:443").0,
        Got::Http(0, String::new())
    );
    eprintln!("release: {released:?} from the command to the next request going out");

    // Notice: only the probe hosts' addresses go to the page; the rest works.
    ok(
        "ip.subscriber-notice.profile.set",
        json!({"id": "atraso", "mode": "notice", "intercept": "probes"}),
    );
    ok(
        "ip.firewall.address-list.add",
        json!({"list": "sn-probe", "address": "198.51.100.7", "timeout": "1h"}),
    );
    ok(
        "ip.firewall.address-list.add",
        json!({"list": "bloqueados", "address": "100.64.0.10"}),
    );
    wait_for("the notice", || {
        matches!(
            get(sub_p, "198.51.100.7:80", "captive.apple.com", "/").0,
            Got::Http(302, _)
        )
    });
    assert_eq!(
        get(sub_p, "198.51.100.8:80", "example.com", "/").0,
        Got::Http(204, String::new()),
        "other sites work"
    );
    assert_eq!(
        connect(sub_p, "198.51.100.8:443").0,
        Got::Http(0, String::new()),
        "HTTPS works"
    );
    // Seen ("continue"): the probes go out again for the interval.
    assert_eq!(
        get(sub_p, "100.64.0.1:8880", "100.64.0.1", "/seen").0,
        Got::Http(200, String::new())
    );
    assert_eq!(
        get(
            sub_p,
            "198.51.100.7:80",
            "connectivitycheck.gstatic.com",
            "/generate_204"
        )
        .0,
        Got::Http(204, String::new())
    );

    // Throttle: the member gets a dynamic queue at the profile's rate.
    ok(
        "ip.subscriber-notice.profile.set",
        json!({"id": "atraso", "mode": "throttle", "rate_limit": "1M/1M"}),
    );
    let q = ok("queue.simple.list", json!({"origin": "notice"}));
    assert!(
        q["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["target"] == "100.64.0.10"),
        "{q}"
    );

    // 100 000 subscribers in the list: a member still gets the page at once,
    // and a release is still one element.
    ok(
        "ip.subscriber-notice.profile.set",
        json!({"id": "atraso", "mode": "block"}),
    );
    let start = Instant::now();
    for k in 0..10u32 {
        let steps: Vec<Value> = (k * 10_000..(k + 1) * 10_000)
            .map(|i| {
                let a = std::net::Ipv4Addr::from(0x0a00_0000 + i);
                json!({"command": "ip.firewall.address-list.add", "params": {"list": "bloqueados", "address": a.to_string()}})
            })
            .collect();
        batch(steps);
    }
    let loaded = start.elapsed();
    wait_for("100k: the page", || {
        matches!(
            get(sub_p, "198.51.100.7:80", "captive.apple.com", "/").0,
            Got::Http(302, _)
        )
    });
    let (got, probe) = get(
        sub_p,
        "198.51.100.7:80",
        "connectivitycheck.gstatic.com",
        "/generate_204",
    );
    assert!(matches!(got, Got::Http(302, _)));
    let (_, refused) = connect(sub_p, "198.51.100.7:443");
    let start = Instant::now();
    let id = ok(
        "ip.firewall.address-list.add",
        json!({"list": "bloqueados", "address": "100.64.2.99", "timeout": "1h"}),
    )["id"]
        .clone();
    ok("ip.firewall.address-list.remove", json!({"id": id}));
    let dynamic = start.elapsed();
    eprintln!(
        "100k listed: loaded (10 batches of 10 000, commit and kernel) {loaded:?}; a probe answered by the portal in {probe:?}; \
         HTTPS refused in {refused:?}; one dynamic entry in and out {dynamic:?}"
    );
    assert!(refused < Duration::from_millis(200));
}

#[test]
fn query_helper() {
    common::query_helper();
}

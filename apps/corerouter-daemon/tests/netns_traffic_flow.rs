//! G4.4b: Traffic Flow against a real kernel. A subscriber in its own
//! namespace opens TCP and UDP connections to a server in a third one,
//! through this namespace's source NAT; `corerouter-daemon --backend
//! linux` reads the conntrack events and exports them to two collectors
//! written here (NetFlow v9 over UDP, IPFIX over TCP), which decode and
//! check every field that matters — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_traffic_flow -- --nocapture
//! ```
//!
//! ```text
//!  [B: subscriber] sub0 ───veth─── lan0  [here: router, snat]  wan0 ───veth─── srv0 [C: server]
//!  100.64.0.1/24                 100.64.0.254/24       192.0.2.1/24            192.0.2.2/24
//! ```
//!
//! It ends with a burst (`COREROUTER_FLOW_BURST` connections, 20 000 by
//! default) and prints what was measured: flows exported per second, the
//! daemon's CPU, queue drops and kernel overruns.
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
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::*;
use corerouter_proto_flow::decode::{Decoder, to_record};
use corerouter_proto_flow::{Direction, NatEventType, Record};
use serde_json::{Value, json};

const PORT: &str = "7995";

fn run(command: &str, params: Value) -> Result<Value, String> {
    common::client(&format!("127.0.0.1:{PORT}"), common::token_of(None)).and_then(|mut c| {
        c.call(
            "engine.execute",
            json!({"command": command, "params": params}),
        )
    })
}

fn sh(pid: Option<u32>, script: &str) {
    let out = in_ns(pid, "sh").args(["-c", script]).output().unwrap();
    assert!(
        out.status.success(),
        "{script}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Run `f` on a thread inside the namespace of `pid`.
fn within<T: Send + 'static>(pid: u32, f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::spawn(move || {
        let ns = std::fs::File::open(format!("/proc/{pid}/ns/net")).unwrap();
        nix::sched::setns(ns, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        f()
    })
    .join()
    .unwrap()
}

type Got = Arc<Mutex<Vec<Record>>>;

/// A NetFlow v9 / IPFIX collector on UDP.
fn udp_collector(port: u16) -> (Got, Arc<Mutex<u64>>) {
    let sock = UdpSocket::bind(("127.0.0.1", port)).unwrap();
    let got: Got = Arc::default();
    let packets = Arc::new(Mutex::new(0u64));
    let (g, p) = (got.clone(), packets.clone());
    std::thread::spawn(move || {
        let mut d = Decoder::new();
        let mut buf = vec![0u8; 65_536];
        while let Ok(n) = sock.recv(&mut buf) {
            *p.lock().unwrap() += 1;
            let m = d.decode(&buf[..n]).unwrap();
            let recs: Vec<Record> = m.records.iter().filter_map(|r| to_record(r, &m)).collect();
            g.lock().unwrap().extend(recs);
        }
    });
    (got, packets)
}

/// An IPFIX collector on TCP (RFC 7011 §10.4: messages back to back, each
/// framed by its own length field).
fn tcp_collector(port: u16) -> Got {
    let l = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let got: Got = Arc::default();
    let g = got.clone();
    std::thread::spawn(move || {
        while let Ok((mut s, _)) = l.accept() {
            let mut d = Decoder::new();
            let mut head = [0u8; 4];
            while s.read_exact(&mut head).is_ok() {
                let len = usize::from(u16::from_be_bytes([head[2], head[3]]));
                let mut msg = head.to_vec();
                msg.resize(len.max(4), 0);
                if s.read_exact(&mut msg[4..]).is_err() {
                    break;
                }
                let m = d.decode(&msg).unwrap();
                let recs: Vec<Record> = m.records.iter().filter_map(|r| to_record(r, &m)).collect();
                g.lock().unwrap().extend(recs);
            }
        }
    });
    got
}

fn wait(what: &str, secs: u64, mut ok: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while Instant::now() < deadline {
        if ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    panic!("timed out waiting for {what}");
}

fn ipv4(s: &str) -> IpAddr {
    s.parse().unwrap()
}

/// The daemon's CPU time so far (utime + stime, clock ticks of 10 ms).
fn cpu_ms(pid: u32) -> u64 {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let after = stat.rsplit_once(')').unwrap().1;
    let f: Vec<&str> = after.split_whitespace().collect();
    (f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap()) * 10
}

fn rss_kb(pid: u32) -> u64 {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    s.lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse().ok())
        .unwrap_or(0)
}

/// Not a test: `common::call` re-runs test binaries with it.
#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn conntrack_flows_with_nat_reach_both_collectors() {
    if !in_netns() {
        return;
    }
    if Command::new("nft").arg("--version").output().is_err() {
        eprintln!("skipped: the `nft` program (nftables) is not installed");
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    let b = namespace_b();
    let c = namespace_b();
    let (bp, cp) = (b.0.id(), c.0.id());
    ip(
        None,
        &[
            "link", "add", "lan0", "type", "veth", "peer", "name", "sub0",
        ],
    );
    ip(
        None,
        &[
            "link", "add", "wan0", "type", "veth", "peer", "name", "srv0",
        ],
    );
    ip(None, &["link", "set", "sub0", "netns", &bp.to_string()]);
    ip(None, &["link", "set", "srv0", "netns", &cp.to_string()]);
    for (pid, dev, addr, gw) in [
        (bp, "sub0", "100.64.0.1/24", "100.64.0.254"),
        (cp, "srv0", "192.0.2.2/24", "192.0.2.1"),
    ] {
        ip(Some(pid), &["link", "set", "lo", "up"]);
        ip(Some(pid), &["addr", "add", addr, "dev", dev]);
        ip(Some(pid), &["link", "set", dev, "up"]);
        ip(Some(pid), &["route", "add", "default", "via", gw]);
    }
    // Veths whose peers live in other namespaces are not CoreRouter's
    // (G1.18): the kernel side is set up here, the daemon leaves it alone.
    for (a, i) in [("100.64.0.254/24", "lan0"), ("192.0.2.1/24", "wan0")] {
        ip(None, &["addr", "add", a, "dev", i]);
        ip(None, &["link", "set", i, "up"]);
    }
    sh(None, "echo 1 > /proc/sys/net/ipv4/ip_forward");
    // Source NAT of the subscriber to the router's public address.
    sh(
        None,
        "nft add table ip t && nft add chain ip t post '{ type nat hook postrouting priority 100; }' \
         && nft add rule ip t post oifname wan0 snat to 192.0.2.1",
    );
    // Connections end fast, so their DESTROY events come within the test.
    for (k, v) in [
        ("nf_conntrack_tcp_timeout_time_wait", "1"),
        ("nf_conntrack_tcp_timeout_fin_wait", "1"),
        ("nf_conntrack_tcp_timeout_close", "1"),
        ("nf_conntrack_udp_timeout", "1"),
        ("nf_conntrack_udp_timeout_stream", "1"),
    ] {
        sh(None, &format!("echo {v} > /proc/sys/net/netfilter/{k}"));
    }

    let (v9, v9_packets) = udp_collector(2055);
    let ipfix = tcp_collector(4739);

    let dir = std::env::temp_dir().join(format!("g44b-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let log = std::fs::File::create(std::env::temp_dir().join("g44b-netns.log")).unwrap();
    let mut cmd = Command::new(DAEMON);
    cmd.args([
        "--backend",
        "linux",
        "--no-discovery",
        "--control",
        PORT,
        "--config-dir",
    ])
    .arg(&dir)
    .arg("--token-file")
    .arg(common::token_file(None, &dir))
    .env("RUST_LOG", "info")
    .stdout(Stdio::null())
    .stderr(log);
    let daemon = Kill(cmd.spawn().unwrap());
    let dpid = daemon.0.id();
    wait_for("the daemon", || run("interface.list", json!({})).is_ok());
    let udp_target = run(
        "ip.traffic-flow.target.add",
        json!({"dst_address": "127.0.0.1", "port": 2055, "version": 9}),
    )
    .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    run(
        "ip.traffic-flow.target.add",
        json!({"dst_address": "127.0.0.1", "port": 4739, "version": "ipfix", "transport": "tcp"}),
    )
    .unwrap();
    run("ip.traffic-flow.set", json!({"enabled": true, "nat_events": true})).unwrap();
    wait("the exporter", 15, || {
        run("ip.traffic-flow.get", json!({})).unwrap()["state"] == "running"
    });

    // The server: echo for TCP, a sink for UDP.
    within(cp, || {
        let l = TcpListener::bind("192.0.2.2:8080").unwrap();
        std::thread::spawn(move || {
            while let Ok((mut s, _)) = l.accept() {
                let mut buf = vec![0u8; 20_000];
                let mut n = 0;
                while n < 10_000 {
                    match s.read(&mut buf[n..]) {
                        Ok(0) | Err(_) => break,
                        Ok(k) => n += k,
                    }
                }
                let _ = s.write_all(&buf[..n]);
            }
        });
    });
    // The subscriber: 10 kB each way over TCP, then three UDP datagrams.
    within(bp, || {
        let mut s = TcpStream::connect("192.0.2.2:8080").unwrap();
        s.write_all(&[7u8; 10_000]).unwrap();
        let mut back = vec![0u8; 10_000];
        s.read_exact(&mut back).unwrap();
        drop(s);
        let u = UdpSocket::bind("100.64.0.1:5353").unwrap();
        for _ in 0..3 {
            u.send_to(&[1u8; 100], "192.0.2.2:53").unwrap();
        }
    });

    let has = |got: &Got, f: &dyn Fn(&Record) -> bool| got.lock().unwrap().iter().any(f);
    let tcp_up = |r: &Record| {
        matches!(r, Record::Flow(f) if f.protocol == 6 && f.direction == Direction::Initiator
            && f.src == ipv4("100.64.0.1") && f.dst == ipv4("192.0.2.2") && f.dst_port == 8080
            && f.post_src == ipv4("192.0.2.1") && f.octets >= 10_000)
    };
    let tcp_down = |r: &Record| {
        matches!(r, Record::Flow(f) if f.protocol == 6 && f.direction == Direction::Reverse
            && f.src == ipv4("192.0.2.2") && f.dst == ipv4("192.0.2.1")
            && f.post_dst == ipv4("100.64.0.1") && f.octets >= 10_000)
    };
    let nat_create = |r: &Record| {
        matches!(r, Record::Nat(n) if n.event == NatEventType::Nat44SessionCreate
            && n.protocol == 6 && n.src == Ipv4Addr::new(100, 64, 0, 1)
            && n.post_src == Ipv4Addr::new(192, 0, 2, 1)
            // Marco Civil art. 14 by default: no destination.
            && n.dst == Ipv4Addr::UNSPECIFIED && n.dst_port == 0)
    };
    let nat_delete = |r: &Record| matches!(r, Record::Nat(n) if n.event == NatEventType::Nat44SessionDelete && n.protocol == 6 && n.start_ms > 0);
    let udp = |r: &Record| {
        matches!(r, Record::Flow(f) if f.protocol == 17 && f.src_port == 5353 && f.packets == 3
            && f.post_src == ipv4("192.0.2.1"))
    };
    for (name, got) in [("v9/udp", &v9), ("ipfix/tcp", &ipfix)] {
        wait(&format!("{name}: NAT44 create"), 20, || {
            has(got, &nat_create)
        });
        wait(
            &format!("{name}: the TCP flows and the NAT44 delete"),
            40,
            || has(got, &tcp_up) && has(got, &tcp_down) && has(got, &nat_delete),
        );
        wait(&format!("{name}: the UDP flow"), 40, || has(got, &udp));
    }
    // Times come from the kernel's stamps: a real duration, not 0.
    let first = v9
        .lock()
        .unwrap()
        .iter()
        .find(|r| tcp_up(r))
        .cloned()
        .unwrap();
    let Record::Flow(f) = first else { panic!() };
    assert!(
        f.end_ms >= f.start_ms && f.start_ms > 1_600_000_000_000,
        "{f:?}"
    );

    let st = run("ip.traffic-flow.stats", json!({})).unwrap();
    assert_eq!(st["source"], "conntrack", "{st}");
    assert_eq!(st["accounting"], true, "nf_conntrack_acct turned on: {st}");
    assert_eq!(st["queue_dropped"], 0, "{st}");
    let top = run("ip.traffic-flow.top", json!({})).unwrap();
    assert_eq!(top[0]["address"], "100.64.0.1", "{top}");
    let targets = run("ip.traffic-flow.target.list", json!({})).unwrap();
    assert!(
        targets
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t["state"] == "sending"),
        "{targets}"
    );

    // No leak: a removed target gets nothing more.
    run("ip.traffic-flow.target.remove", json!({"id": udp_target})).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    let before = *v9_packets.lock().unwrap();
    let ipfix_before = ipfix.lock().unwrap().len();
    within(bp, || {
        let u = UdpSocket::bind("100.64.0.1:6000").unwrap();
        u.send_to(&[1u8; 10], "192.0.2.2:53").unwrap();
    });
    wait("the IPFIX collector, still configured", 30, || {
        ipfix.lock().unwrap().len() > ipfix_before
    });
    assert_eq!(
        *v9_packets.lock().unwrap(),
        before,
        "the removed v9 target got packets"
    );

    // The burst: N UDP connections opened as fast as one thread can, then
    // all deleted at once through ctnetlink (as `conntrack -D` would), so
    // the DESTROY events come in a burst too instead of trickling out of
    // the kernel's garbage collector.
    let n: u32 = std::env::var("COREROUTER_FLOW_BURST")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000);
    let count = |got: &Got, f: &dyn Fn(&Record) -> bool| {
        got.lock().unwrap().iter().filter(|r| f(r)).count()
    };
    let burst = |r: &Record| match r {
        Record::Flow(f) => (7000..7010).contains(&f.src_port) && f.protocol == 17,
        Record::Nat(x) => (7000..7010).contains(&x.src_port),
        Record::PortBlock(_) | Record::NatLimit(_) => false,
    };
    let is_create = |r: &Record| matches!(r, Record::Nat(x) if (7000..7010).contains(&x.src_port) && x.event == NatEventType::Nat44SessionCreate);
    let is_delete = |r: &Record| matches!(r, Record::Nat(x) if (7000..7010).contains(&x.src_port) && x.event == NatEventType::Nat44SessionDelete && x.start_ms > 0);
    let is_flow = |r: &Record| matches!(r, Record::Flow(f) if (7000..7010).contains(&f.src_port));
    for (k, v) in [
        ("nf_conntrack_udp_timeout", "600"),
        ("nf_conntrack_udp_timeout_stream", "600"),
    ] {
        sh(None, &format!("echo {v} > /proc/sys/net/netfilter/{k}"));
    }
    let st0 = run("ip.traffic-flow.stats", json!({})).unwrap();
    let cpu0 = cpu_ms(dpid);
    let t0 = Instant::now();
    within(bp, move || {
        // 50 000 destination ports per source port, up to 10 source ports.
        let socks: Vec<UdpSocket> = (0..n.div_ceil(50_000).min(10))
            .map(|i| UdpSocket::bind(("100.64.0.1", 7000 + i as u16)).unwrap())
            .collect();
        for i in 0..n {
            let port = 10_000 + (i % 50_000) as u16;
            let u = &socks[(i / 50_000) as usize];
            let _ = u.send_to(&[0u8; 64], ("192.0.2.2", port));
        }
    });
    let opened = t0.elapsed();
    // Until all came, or none for 2 s (a kernel overrun loses some: the
    // deletes below still carry their start).
    let (mut last, mut still) = (0, Instant::now());
    while count(&ipfix, &is_create) < n as usize && still.elapsed() < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(50));
        let now = count(&ipfix, &is_create);
        if now != last {
            (last, still) = (now, Instant::now());
        }
    }
    let creates_in = t0.elapsed();
    let creates = count(&ipfix, &is_create);
    let mine: Vec<_> = corerouter_hal_linux::ctnl::dump()
        .unwrap()
        .into_iter()
        .filter(|c| (7000..7010).contains(&c.orig.src_port))
        .collect();
    let t1 = Instant::now();
    // In blocks the collector keeps up with: the kernel sends a destroy
    // event per connection, and 20 000 at once (0.2–0.3 s) overran the
    // event socket on a busy CI runner. An unprivileged namespace cannot
    // force its buffer past the host's `rmem_max` (~208 KiB), so 12% of the
    // deletes were lost (`kernel_overruns`). What the test checks is that
    // every connection is reported, not the kernel's burst rate.
    for block in mine.chunks(1000) {
        corerouter_hal_linux::ctnl::delete(block).unwrap();
        std::thread::sleep(Duration::from_millis(40));
    }
    let deleted = t1.elapsed();
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline
        && (count(&ipfix, &is_delete) < creates.max(mine.len())
            || count(&ipfix, &is_flow) < mine.len())
    {
        std::thread::sleep(Duration::from_millis(50));
    }
    let deletes_in = t1.elapsed();
    let cpu = cpu_ms(dpid) - cpu0;
    // The status is refreshed every second.
    std::thread::sleep(Duration::from_millis(1500));
    let total = count(&ipfix, &burst);
    let st = run("ip.traffic-flow.stats", json!({})).unwrap();
    let delta = |k: &str| st[k].as_u64().unwrap_or(0) - st0[k].as_u64().unwrap_or(0);
    eprintln!(
        "MEASURED burst of {n} UDP connections: opened in {:.3} s; {creates} NAT creates exported {:.2} s after the start; \
         {} conntrack deletes in {:.3} s, then {} NAT deletes and {} flows exported {:.2} s after the first delete \
         ({:.0} records/s); {total} records, daemon CPU {cpu} ms ({:.1} us/record); RSS {} kB; \
         queue_dropped +{}; kernel_overruns +{}; events +{}",
        opened.as_secs_f64(),
        creates_in.as_secs_f64(),
        mine.len(),
        deleted.as_secs_f64(),
        count(&ipfix, &is_delete),
        count(&ipfix, &is_flow),
        deletes_in.as_secs_f64(),
        (2 * mine.len()) as f64 / deletes_in.as_secs_f64(),
        cpu as f64 * 1000.0 / total.max(1) as f64,
        rss_kb(dpid),
        delta("queue_dropped"),
        delta("kernel_overruns"),
        delta("events"),
    );
    // Every connection the kernel had is reported: its flow and its NAT
    // delete (which carries the start: complete even if a create was lost).
    assert_eq!(count(&ipfix, &is_flow), mine.len(), "{st}");
    assert_eq!(count(&ipfix, &is_delete), mine.len(), "{st}");
    assert!(
        mine.len() >= n as usize * 99 / 100,
        "the kernel tracked {} of {n}",
        mine.len()
    );

    drop(daemon);
    let _ = std::fs::remove_dir_all(&dir);
}

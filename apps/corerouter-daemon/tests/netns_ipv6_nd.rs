//! G3.9ha: a `--backend linux` daemon sends Router Advertisements on a LAN
//! (`ipv6.nd.add`), and a Linux host across a veth autoconfigures from
//! them — address by SLAAC (RFC 4862 §5.5.3) and default route — inside
//! throwaway network namespaces, no root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_ipv6_nd
//! ```
//!
//! ```text
//!   this ns: daemon                       namespace B: a plain host
//!   lan0 2001:db8:5::1/64 ──── veth ──── host0 (accept_ra=1, forwarding 0)
//! ```
//!
//! Then: the host's Router Solicitation is counted, the RA's values reach
//! the host's kernel (hop limit, MTU), and disabling the entry sends the
//! final RA (Router Lifetime 0, RFC 4861 §6.2.5) that takes the default
//! route away at once and deprecates the address (RFC 9096 §3.5).
//!
//! Last, a DHCPv6 server in namespace C delegates a /56 on `wan0`; the LAN
//! address comes from that pool, and the host gets its /64 by SLAAC with
//! the delegation's lifetimes (RFC 9096 §3.4) and the RA's RDNSS/DNSSL
//! (RFC 8106), read by a raw socket in B.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use common::*;
use corerouter_hal::dhcp::Dhcp6Responder;
use corerouter_proto_dhcp::lab6::LabServer6;
use corerouter_proto_dhcp::v6;
use corerouter_proto_pppoe::nd;
use serde_json::{Value, json};
use socket2::{Domain, Protocol, Socket, Type};

const PORT: &str = "7989";

fn run(command: &str, params: Value) -> Result<Value, String> {
    common::client(&format!("127.0.0.1:{PORT}"), common::token_of(None)).and_then(|mut c| {
        c.call(
            "engine.execute",
            json!({"command": command, "params": params}),
        )
    })
}

fn ip_out(pid: Option<u32>, args: &[&str]) -> String {
    let out = in_ns(pid, "ip").args(args).output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn sysctl_b(pid: Option<u32>, key: &str) -> String {
    let out = in_ns(pid, "cat")
        .arg(format!("/proc/sys/net/ipv6/conf/host0/{key}"))
        .output()
        .unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn nd_row() -> Value {
    run("ipv6.nd.list", json!({})).unwrap()["interfaces"][0].clone()
}

fn enter(pid: u32) {
    let ns = std::fs::File::open(format!("/proc/{pid}/ns/net")).unwrap();
    nix::sched::setns(ns, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
}

/// A DHCPv6 server (the lab's: prefix 2001:db8:1:100::/56, valid 3600 s)
/// on `srv0` inside the namespace of `pid`, until `stop`.
fn dhcp6_server_in(pid: u32, stop: Arc<AtomicBool>) {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        enter(pid);
        let ifindex = nix::net::if_::if_nametoindex("srv0").unwrap();
        let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        sock.set_only_v6(true).unwrap();
        sock.bind_device(Some(b"srv0")).unwrap();
        sock.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 547)).into())
            .unwrap();
        sock.join_multicast_v6(&corerouter_hal::dhcp::ALL_DHCP_SERVERS, ifindex)
            .unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let sock: std::net::UdpSocket = sock.into();
        ready_tx.send(()).unwrap();
        let lab = LabServer6::default();
        let port = "ether1".parse().unwrap();
        let mut buf = [0u8; 2048];
        while !stop.load(Ordering::Relaxed) {
            let Ok((n, SocketAddr::V6(from))) = sock.recv_from(&mut buf) else {
                continue;
            };
            let Ok(m) = v6::decode_client(&buf[..n]) else {
                continue;
            };
            let mac = m
                .client_id
                .as_deref()
                .and_then(v6::duid_mac)
                .unwrap_or([0; 6]);
            for d in lab.answer(&port, mac, &buf[..n]) {
                let _ = sock.send_to(
                    &d.payload,
                    SocketAddrV6::new(*from.ip(), from.port(), 0, ifindex),
                );
            }
        }
    });
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
}

/// The first RA on `host0` in the namespace of `pid` that has an RDNSS
/// option, read by a raw ICMPv6 socket (the kernel ignores RDNSS).
fn ra_with_dns_in(pid: u32) -> std::sync::mpsc::Receiver<nd::ParsedRa> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        enter(pid);
        let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).unwrap();
        sock.bind_device(Some(b"host0")).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let sock: std::net::UdpSocket = sock.into();
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut buf = [0u8; 1500];
        while Instant::now() < deadline {
            let Ok((n, SocketAddr::V6(from))) = sock.recv_from(&mut buf) else {
                continue;
            };
            if let Ok(ra) = nd::parse_ra_icmp(*from.ip(), &buf[..n])
                && !ra.rdnss.is_empty()
            {
                let _ = tx.send(ra);
                return;
            }
        }
    });
    rx
}

#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn linux_router_advertisement_gives_a_host_slaac_and_a_default_route() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    let b = namespace_b();
    let bpid = Some(b.0.id());
    ip(
        None,
        &[
            "link", "add", "lan0", "type", "veth", "peer", "name", "host0",
        ],
    );
    ip(
        None,
        &["link", "set", "host0", "netns", &b.0.id().to_string()],
    );
    ip(
        bpid,
        &["link", "set", "host0", "address", "02:00:00:00:00:05"],
    );
    ip(bpid, &["link", "set", "lo", "up"]);
    ip(None, &["link", "set", "lan0", "up"]);
    // The WAN: a DHCPv6 server in C, for the last part.
    let c_ns = namespace_b();
    let cpid = Some(c_ns.0.id());
    ip(
        None,
        &[
            "link", "add", "wan0", "type", "veth", "peer", "name", "srv0",
        ],
    );
    ip(
        None,
        &["link", "set", "srv0", "netns", &c_ns.0.id().to_string()],
    );
    ip(cpid, &["link", "set", "lo", "up"]);
    ip(cpid, &["link", "set", "srv0", "up"]);
    ip(None, &["link", "set", "wan0", "up"]);

    let dir = std::env::temp_dir().join(format!("g39ha-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let log = std::fs::File::create(std::env::temp_dir().join("g39ha-netns.log")).unwrap();
    let mut c = Command::new(DAEMON);
    c.args([
        "--backend",
        "linux",
        "--no-discovery",
        "--manage",
        "lan0,wan0",
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
    let daemon = Kill(c.spawn().unwrap());
    wait_for("the daemon", || run("interface.list", json!({})).is_ok());

    run(
        "ip.address.add",
        json!({"address": "2001:db8:5::1/64", "interface": "lan0"}),
    )
    .unwrap();
    let r = run(
        "ipv6.nd.add",
        json!({"interface": "lan0", "ra_interval": "3s-4s", "hop_limit": 61, "mtu": 1400}),
    )
    .unwrap();
    assert_eq!(r["warnings"], json!([]), "{r}");
    let id = r["id"].clone();
    // The host comes up now: its kernel sends Router Solicitations (the
    // veth had no carrier, so lan0's link-local is only now checked).
    assert_eq!(sysctl_b(bpid, "accept_ra"), "1");
    let t0 = Instant::now();
    ip(bpid, &["link", "set", "host0", "up"]);
    wait_for("lan0's link-local after DAD", || {
        let s = ip_out(None, &["-6", "addr", "show", "dev", "lan0"]);
        s.contains("fe80::") && !s.contains("tentative")
    });
    let router_ll = ip_out(
        None,
        &["-6", "-o", "addr", "show", "dev", "lan0", "scope", "link"],
    )
    .split_whitespace()
    .nth(3)
    .unwrap()
    .split('/')
    .next()
    .unwrap()
    .to_owned();

    // RFC 4862 §5.5.3: prefix 2001:db8:5::/64 + EUI-64 of 02:00:00:00:00:05.
    wait_for("the host's SLAAC address and default route", || {
        ip_out(bpid, &["-6", "addr", "show", "dev", "host0"]).contains("2001:db8:5::ff:fe00:5/64")
            && ip_out(bpid, &["-6", "route", "show", "default"])
                .contains(&format!("via {router_ll} dev host0 proto ra"))
    });
    eprintln!("SLAAC and default route after {:?} (medido)", t0.elapsed());
    // The RA's values in the host's kernel (RFC 4861 §6.3.4).
    assert_eq!(sysctl_b(bpid, "hop_limit"), "61");
    assert_eq!(sysctl_b(bpid, "mtu"), "1400");
    let row = nd_row();
    assert_eq!(row["state"], "sending", "{row}");
    assert_eq!(row["prefixes"], json!(["2001:db8:5::/64"]));
    wait_for("the host's RS counted", || {
        nd_row()["rs_received"].as_u64() > Some(0)
    });
    assert_eq!(run("ipv6.nd.list", json!({})).unwrap()["sender"], "running");
    let pl = run("ipv6.nd.prefix.list", json!({})).unwrap();
    assert_eq!(pl[0]["origin"], "address", "{pl}");

    // Disabled: the final RA (Router Lifetime 0) removes the default route
    // at once and deprecates the address (preferred 0).
    run("ipv6.nd.disable", json!({"id": id})).unwrap();
    wait_for("the default route gone and the address deprecated", || {
        !ip_out(bpid, &["-6", "route", "show", "default"]).contains("proto ra")
            && ip_out(bpid, &["-6", "addr", "show", "dev", "host0"]).contains("deprecated")
    });

    // DHCPv6-PD: the LAN numbered from the delegated /56, advertised with
    // the delegation's lifetimes (lab: valid 3600 s; RFC 9096 §3.4 caps at
    // 5400) and the RA's DNS options (RFC 8106).
    wait_for("srv0's link-local", || {
        let s = ip_out(cpid, &["-6", "addr", "show", "dev", "srv0"]);
        s.contains("fe80::") && !s.contains("tentative")
    });
    let stop = Arc::new(AtomicBool::new(false));
    dhcp6_server_in(c_ns.0.id(), stop.clone());
    run(
        "ipv6.dhcp-client.add",
        json!({"interface": "wan0", "request": "prefix", "pool_name": "pd"}),
    )
    .unwrap();
    run(
        "ip.address.add",
        json!({"address": "::1/64", "interface": "lan0", "from_pool": "pd"}),
    )
    .unwrap();
    let dns_ra = ra_with_dns_in(b.0.id());
    run(
        "ipv6.nd.set",
        json!({"id": "lan0", "disabled": false, "advertise_dns": true, "dns": "2001:db8::53", "dnssl": "lab.example"}),
    )
    .unwrap();
    wait_for("the host's SLAAC address from the delegated prefix", || {
        ip_out(bpid, &["-6", "addr", "show", "dev", "host0"])
            .contains("2001:db8:1:100:0:ff:fe00:5/64")
    });
    let line = ip_out(bpid, &["-6", "-o", "addr", "show", "dev", "host0"])
        .lines()
        .find(|l| l.contains("2001:db8:1:100:"))
        .unwrap()
        .to_owned();
    let valid: u32 = line
        .split("valid_lft ")
        .nth(1)
        .and_then(|t| t.split("sec").next())
        .and_then(|t| t.parse().ok())
        .unwrap_or(u32::MAX);
    assert!(valid <= 3600, "the delegation's lifetime, not 4w2d: {line}");
    let pl = run("ipv6.nd.prefix.list", json!({"interface": "lan0"})).unwrap();
    assert!(
        pl.as_array()
            .unwrap()
            .iter()
            .any(|r| r["origin"] == "dhcp-pd" && r["prefix"] == "2001:db8:1:100::/64"),
        "{pl}"
    );
    let ra = dns_ra.recv_timeout(Duration::from_secs(30)).unwrap();
    assert_eq!(ra.rdnss, ["2001:db8::53".parse::<Ipv6Addr>().unwrap()]);
    // RFC 8106 §5.1: 3 × MaxRtrAdvInterval (4 s).
    assert_eq!(ra.dns_lifetime, Some(12));
    assert!(
        ra.dnssl_raw.starts_with(b"\x03lab\x07example\x00"),
        "{:?}",
        ra.dnssl_raw
    );
    stop.store(true, Ordering::Relaxed);

    drop(daemon);
    drop(b);
    drop(c_ns);
    ip(None, &["link", "del", "lan0"]);
    let _ = std::fs::remove_dir_all(&dir);
}

//! G4.7b: a `--backend linux` daemon's DHCPv6 client gets an address and a
//! delegated prefix from a DHCPv6 server across a veth, numbers a LAN from
//! that prefix, and controls whether the kernel accepts Router
//! Advertisements — inside throwaway network namespaces, no root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_dhcp6
//! ```
//!
//! ```text
//!   this ns: daemon                      namespace B (threads setns'd into B):
//!   wan0 ─────────── veth ───────────── srv0  DHCPv6 server (UDP 547) and a
//!   lan0 (dummy, numbered from the PD)         router sending RAs for
//!                                              2001:db8:0:1::/64 every 500 ms
//! ```
//!
//! The server answers with the lab server's logic (`proto_dhcp::lab6`):
//! address `2001:db8:0:1::H`, prefix `2001:db8:1:100::/56`.
//! First the kernel is left alone and autoconfigures from the RA — what
//! happened on a real WAN port with no CoreRouter setting — then the
//! daemon's safe default takes that away.
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use corerouter_hal::dhcp::{Dhcp6Responder, eui64, lab_router_mac};
use corerouter_proto_dhcp::lab6::LabServer6;
use corerouter_proto_dhcp::v6;
use serde_json::{Value, json};
use socket2::{Domain, Protocol, Socket, Type};

const PORT: &str = "7996";

fn ip_out(args: &[&str]) -> String {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(out.status.success(), "ip {}", args.join(" "));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn run(command: &str, params: Value) -> Result<Value, String> {
    common::client(&format!("127.0.0.1:{PORT}"), common::token_of(None)).and_then(|mut c| {
        c.call(
            "engine.execute",
            json!({"command": command, "params": params}),
        )
    })
}

fn client_row() -> Value {
    run("ipv6.dhcp-client.list", json!({})).unwrap()[0].clone()
}

fn accept_ra(dev: &str) -> String {
    std::fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{dev}/accept_ra"))
        .unwrap()
        .trim()
        .to_owned()
}

/// The SLAAC address the RA gives wan0: the prefix + EUI-64 of its MAC.
fn slaac(mac: &str) -> String {
    let m: Vec<u8> = mac
        .split(':')
        .map(|b| u8::from_str_radix(b, 16).unwrap())
        .collect();
    let id = eui64(m.try_into().unwrap());
    let a = Ipv6Addr::from((0x2001_0db8_0000_0001u128 << 64) | u128::from(id));
    format!("{a}/64")
}

/// Router Advertisement (RFC 4861 §4.2): router lifetime 1800 s, source
/// link-layer address, Prefix Information 2001:db8:0:1::/64 with L and A.
fn ra(mac: [u8; 6]) -> Vec<u8> {
    let mut p = vec![134, 0, 0, 0, 64, 0x40, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0];
    p.extend_from_slice(&[1, 1]);
    p.extend_from_slice(&mac);
    p.extend_from_slice(&[3, 4, 64, 0xc0]);
    p.extend_from_slice(&2_592_000u32.to_be_bytes());
    p.extend_from_slice(&604_800u32.to_be_bytes());
    p.extend_from_slice(&[0; 4]);
    p.extend_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, 0).octets());
    p
}

struct Server {
    /// DHCPv6 message types received.
    seen: Arc<Mutex<Vec<u8>>>,
    silent: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn enter(pid: u32) {
    let ns = std::fs::File::open(format!("/proc/{pid}/ns/net")).unwrap();
    nix::sched::setns(ns, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
}

/// Serve DHCPv6 and send RAs on `srv0` inside the namespace of `pid`.
fn serve_in(pid: u32) -> Server {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let silent = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let (s2, q2, st2) = (seen.clone(), silent.clone(), stop.clone());
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        enter(pid);
        let ifindex = nix::net::if_::if_nametoindex("srv0").unwrap();
        let sock = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        sock.set_only_v6(true).unwrap();
        sock.set_reuse_address(true).unwrap();
        sock.bind_device(Some(b"srv0")).unwrap();
        sock.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 547)).into())
            .unwrap();
        sock.join_multicast_v6(&v6_servers(), ifindex).unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let sock: std::net::UdpSocket = sock.into();
        ready_tx.send(()).unwrap();
        let lab = LabServer6::default();
        let port = "ether1".parse().unwrap();
        let mut buf = [0u8; 2048];
        while !st2.load(Ordering::Relaxed) {
            let Ok((n, SocketAddr::V6(from))) = sock.recv_from(&mut buf) else {
                continue;
            };
            let bytes = &buf[..n];
            let Ok(m) = v6::decode_client(bytes) else {
                continue;
            };
            s2.lock().unwrap().push(m.kind);
            if q2.load(Ordering::Relaxed) {
                continue;
            }
            let mac = m
                .client_id
                .as_deref()
                .and_then(v6::duid_mac)
                .unwrap_or([0; 6]);
            for d in lab.answer(&port, mac, bytes) {
                let to = SocketAddrV6::new(*from.ip(), from.port(), 0, ifindex);
                let _ = sock.send_to(&d.payload, to);
            }
        }
    });
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    // The router's RAs.
    let st3 = stop.clone();
    std::thread::spawn(move || {
        enter(pid);
        let ifindex = nix::net::if_::if_nametoindex("srv0").unwrap();
        let sock = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6)).unwrap();
        sock.bind_device(Some(b"srv0")).unwrap();
        sock.set_multicast_if_v6(ifindex).unwrap();
        sock.set_multicast_hops_v6(255).unwrap();
        let to = SocketAddrV6::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 0, 0, ifindex);
        let msg = ra(lab_router_mac(1));
        while !st3.load(Ordering::Relaxed) {
            let _ = sock.send_to(&msg, &to.into());
            std::thread::sleep(Duration::from_millis(500));
        }
    });
    Server { seen, silent, stop }
}

fn v6_servers() -> Ipv6Addr {
    corerouter_hal::dhcp::ALL_DHCP_SERVERS
}

#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn linux_dhcpv6_client_gets_address_and_prefix_and_controls_ra() {
    if !in_netns() {
        return;
    }
    ip(None, &["link", "set", "lo", "up"]);
    let b = namespace_b();
    let bpid = Some(b.0.id());
    ip(
        None,
        &[
            "link", "add", "wan0", "type", "veth", "peer", "name", "srv0",
        ],
    );
    ip(
        None,
        &["link", "set", "srv0", "netns", &b.0.id().to_string()],
    );
    ip(None, &["link", "add", "lan0", "type", "dummy"]);
    // The router's link-local is the EUI-64 of its MAC (fe80::dc:ff:fe00:1).
    ip(
        bpid,
        &["link", "set", "srv0", "address", "02:dc:00:00:00:01"],
    );
    ip(bpid, &["link", "set", "lo", "up"]);
    ip(bpid, &["link", "set", "srv0", "up"]);
    ip(None, &["link", "set", "wan0", "up"]);
    ip(None, &["link", "set", "lan0", "up"]);
    wait_for("srv0's link-local after DAD", || {
        let out = in_ns(bpid, "ip")
            .args(["-6", "addr", "show", "dev", "srv0"])
            .output()
            .unwrap();
        let s = String::from_utf8_lossy(&out.stdout).into_owned();
        s.contains("fe80::") && !s.contains("tentative")
    });
    let server = serve_in(b.0.id());
    // (sysfs shows the namespace it was mounted in: ask `ip`.)
    let link = ip_out(&["-o", "link", "show", "wan0"]);
    let wan_mac = link
        .split("link/ether ")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap();
    let slaac = slaac(wan_mac);

    // Without CoreRouter the kernel takes the RA (accept_ra=1): an address
    // nobody configured shows up on the WAN.
    assert_eq!(accept_ra("wan0"), "1");
    wait_for("the kernel's own SLAAC address", || {
        ip_out(&["-6", "addr", "show", "dev", "wan0"]).contains(&slaac)
    });

    let dir = std::env::temp_dir().join(format!("g47b-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let log = std::fs::File::create(std::env::temp_dir().join("g47b-netns.log")).unwrap();
    let mut c = Command::new(DAEMON);
    c.args([
        "--backend",
        "linux",
        "--no-discovery",
        "--manage",
        "wan0,lan0",
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

    // The safe default (auto, no DHCPv6 client): RA off on every managed
    // interface, and what the kernel learned before is gone.
    assert_eq!(accept_ra("wan0"), "0");
    assert_eq!(accept_ra("lan0"), "0");
    assert!(!ip_out(&["-6", "addr", "show", "dev", "wan0"]).contains(&slaac));
    assert!(!ip_out(&["-6", "route", "show"]).contains("proto ra"));

    // A WAN client: RA accepted on wan0 (accept_ra=2, even if forwarding).
    let id = run(
        "ipv6.dhcp-client.add",
        json!({"interface": "wan0", "request": "address,prefix", "pool_name": "pd"}),
    )
    .unwrap()["id"]
        .clone();
    run(
        "ip.address.add",
        json!({"address": "::1/64", "interface": "lan0", "from_pool": "pd"}),
    )
    .unwrap();
    assert_eq!(accept_ra("wan0"), "2");
    assert_eq!(accept_ra("lan0"), "0");
    wait_for("a lease", || client_row()["status"] == "bound");
    let row = client_row();
    let address = row["address"].as_str().unwrap().to_owned();
    assert!(
        address.starts_with("2001:db8:0:1::") && address.ends_with("/128"),
        "{row}"
    );
    assert_eq!(row["prefix"], "2001:db8:1:100::/56");
    assert_eq!(row["dhcp_server"], "fe80::dc:ff:fe00:1");

    // In this namespace's kernel: the /128, the LAN address from the pool,
    // and (from the RA) the SLAAC address and the default route.
    wait_for("the RA again", || {
        ip_out(&["-6", "addr", "show", "dev", "wan0"]).contains(&slaac)
            && ip_out(&["-6", "route", "show"])
                .contains("default via fe80::dc:ff:fe00:1 dev wan0 proto ra")
    });
    assert!(ip_out(&["-6", "addr", "show", "dev", "wan0"]).contains(&address));
    assert!(ip_out(&["-6", "addr", "show", "dev", "lan0"]).contains("2001:db8:1:100::1/64"));
    // … and the lists say where each came from.
    let addrs = run("ip.address.list", json!({})).unwrap();
    let origin = |a: &str| {
        addrs
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["address"] == a)
            .map(|r| {
                (
                    r["origin"].as_str().unwrap().to_owned(),
                    r["flags"].as_str().unwrap().to_owned(),
                )
            })
    };
    assert_eq!(origin(&slaac), Some(("ra".into(), "D".into())), "{addrs}");
    assert_eq!(origin(&address), Some(("dhcpv6".into(), "D".into())));
    assert_eq!(
        origin("2001:db8:1:100::1/64"),
        Some(("pool".into(), String::new()))
    );
    let routes = run("ip.route.list", json!({})).unwrap();
    assert!(
        routes
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["dst_address"] == "::/0"
                && r["origin"] == "ra"
                && r["gateway"] == "fe80::dc:ff:fe00:1%wan0"),
        "{routes}"
    );

    // Renew reaches the server.
    let before = server
        .seen
        .lock()
        .unwrap()
        .iter()
        .filter(|k| **k == v6::msg::RENEW)
        .count();
    run("ipv6.dhcp-client.renew", json!({"id": id})).unwrap();
    wait_for("the Renew", || {
        server
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|k| **k == v6::msg::RENEW)
            .count()
            > before
            && client_row()["status"] == "bound"
    });

    // Release with the server quiet: Release sent, the /128 and the LAN
    // address leave the kernel.
    server.silent.store(true, Ordering::Relaxed);
    run("ipv6.dhcp-client.release", json!({"id": id})).unwrap();
    wait_for("the Release", || {
        server.seen.lock().unwrap().contains(&v6::msg::RELEASE)
    });
    assert!(!ip_out(&["-6", "addr", "show", "dev", "wan0"]).contains(&address));
    assert!(!ip_out(&["-6", "addr", "show", "dev", "lan0"]).contains("2001:db8:1:100::1"));

    // RA off: the kernel forgets the RA's address and route at once.
    run(
        "ipv6.settings.set",
        json!({"accept_router_advertisements": "no"}),
    )
    .unwrap();
    assert_eq!(accept_ra("wan0"), "0");
    assert!(!ip_out(&["-6", "addr", "show", "dev", "wan0"]).contains(&slaac));
    assert!(!ip_out(&["-6", "route", "show"]).contains("proto ra"));

    drop(daemon);
    drop(server);
    ip(None, &["link", "del", "wan0"]);
    ip(None, &["link", "del", "lan0"]);
    let _ = std::fs::remove_dir_all(&dir);
}

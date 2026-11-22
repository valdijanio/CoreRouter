//! G4.3cc: one PPPoE subscriber policed by the XDP program while 1, 4, 8
//! and 16 senders, each pinned to its own CPU, send its frames at once
//! (generic XDP runs on the sender's CPU, so every CPU updates the same
//! policer state). The error of what passed against the rate says whether
//! the state survives the race. Root only, like `xdp_root.rs`
//! (`COREROUTER_XDP_ROOT=1`).
//!
//! The file uses only what the G4.3c data plane already had, so the same
//! test runs on a tree before G4.3cc (the racy policer) for the before and
//! after of `docs/queues.md`.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#![cfg(target_os = "linux")]

use std::process::Command;
use std::time::{Duration, Instant};

use corerouter_dataplane_ebpf_common::parse::{Addr, IPPROTO_UDP};
use corerouter_dataplane_ebpf_common::policer::Rate;
use corerouter_dataplane_ebpf_common::pppoe::{F_ACTIVE, F_IPV4, PPP_IPV4, Session};
use corerouter_dataplane_ebpf_common::testing::{Spec, build, pppoe_frame, with_checksums};
use corerouter_hal_linux::xdp::XdpState;
use corerouter_model::xdp::{XdpInterface, XdpMode};
use corerouter_model::{Config, IfName, Interface, InterfaceKind};

fn enabled() -> bool {
    std::env::var_os("COREROUTER_XDP_ROOT").is_some_and(|v| v == "1")
}

fn sh(args: &[&str]) -> String {
    let out = Command::new(args[0]).args(&args[1..]).output().unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn mac(dev: &str) -> [u8; 6] {
    let t = std::fs::read_to_string(format!("/sys/class/net/{dev}/address")).unwrap();
    let v: Vec<u8> = t
        .trim()
        .split(':')
        .filter_map(|h| u8::from_str_radix(h, 16).ok())
        .collect();
    v.try_into().unwrap()
}

fn ifindex(dev: &str) -> u32 {
    std::fs::read_to_string(format!("/sys/class/net/{dev}/ifindex"))
        .unwrap()
        .trim()
        .parse()
        .unwrap()
}

/// Send `frame` on `dev` from CPU `cpu` for `secs`: frames sent.
fn sender(
    dev: &'static str,
    cpu: usize,
    frame: Vec<u8>,
    secs: f64,
) -> std::thread::JoinHandle<u64> {
    std::thread::spawn(move || {
        let mut set = nix::sched::CpuSet::new();
        let _ = set.set(cpu);
        let _ = nix::sched::sched_setaffinity(nix::unistd::Pid::from_raw(0), &set);
        let sock = socket2::Socket::new(
            socket2::Domain::PACKET,
            socket2::Type::RAW,
            Some(socket2::Protocol::from(i32::from(0x0003u16.to_be()))),
        )
        .unwrap();
        let link = nix::ifaddrs::getifaddrs()
            .unwrap()
            .find(|a| {
                a.interface_name == dev
                    && a.address.as_ref().and_then(|x| x.as_link_addr()).is_some()
            })
            .and_then(|a| a.address.and_then(|x| x.as_link_addr().copied()))
            .unwrap();
        nix::sys::socket::bind(std::os::fd::AsRawFd::as_raw_fd(&sock), &link).unwrap();
        let t = Instant::now();
        let mut sent = 0u64;
        while t.elapsed().as_secs_f64() < secs {
            for _ in 0..32 {
                if nix::sys::socket::send(
                    std::os::fd::AsRawFd::as_raw_fd(&sock),
                    &frame,
                    nix::sys::socket::MsgFlags::empty(),
                )
                .is_ok()
                {
                    sent += 1;
                }
            }
        }
        sent
    })
}

#[test]
fn policer_with_many_cpus_on_one_subscriber() {
    if !enabled() {
        return;
    }
    let _ = Command::new("ip").args(["link", "del", "ra"]).output();
    sh(&[
        "ip", "link", "add", "ra", "type", "veth", "peer", "name", "rb",
    ]);
    sh(&["ip", "link", "set", "ra", "up"]);
    sh(&["ip", "link", "set", "rb", "up"]);
    let mut cfg = Config::default();
    let name: IfName = "ra".parse().unwrap();
    cfg.interfaces.insert(
        name.clone(),
        Interface::new(name.clone(), InterfaceKind::Ethernet),
    );
    cfg.ip.xdp.interfaces.push(XdpInterface {
        interface: name,
        mode: XdpMode::Generic,
        disabled: false,
        comment: String::new(),
    });
    let mut x = XdpState::default();
    x.set_pppoe(true).unwrap();
    x.sync(&cfg).unwrap();
    let rate_bps = 200_000_000u64;
    let s = Session {
        flags: F_ACTIVE | F_IPV4,
        ifindex: ifindex("ra"),
        sid: 1,
        client_mac: mac("rb"),
        server_mac: mac("ra"),
        ipv4: [100, 65, 0, 1],
        up: Rate::mikrotik(rate_bps, 0, 0, 0),
        ..Session::default()
    };
    let ip = with_checksums(build(&Spec {
        vlans: vec![],
        src: Addr::V4(s.ipv4),
        dst: Addr::V4([198, 51, 100, 2]),
        proto: IPPROTO_UDP,
        sport: 5000,
        dport: 9,
        flags: 0,
        payload: 1000,
    }));
    let frame = pppoe_frame(&s, &ip, PPP_IPV4);
    let cpus = std::thread::available_parallelism().map_or(1, |n| n.get());
    for senders in [1usize, 4, 8, 16] {
        x.pppoe_remove(0).unwrap();
        x.pppoe_upsert(0, &s).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let before = x.pppoe_counters(0).unwrap();
        let secs = 3.0;
        let t = Instant::now();
        let hs: Vec<_> = (0..senders)
            .map(|i| sender("rb", i % cpus, frame.clone(), secs))
            .collect();
        let sent: u64 = hs.into_iter().map(|h| h.join().unwrap()).sum();
        let took = t.elapsed().as_secs_f64();
        let after = x.pppoe_counters(0).unwrap();
        let got = after.up_bytes - before.up_bytes;
        let policed = after.up_policed - before.up_policed;
        let depth = s.up.depth as f64;
        let want = rate_bps as f64 / 8.0 * took;
        let err = (got as f64 - depth - want) / want;
        println!(
            "PERF | policer race | {senders} senders on {} CPUs | sent {:.0} kpps | passed {:.1} Mbit/s | policed {policed} | error {:+.2}%",
            senders.min(cpus),
            sent as f64 / took / 1e3,
            got as f64 * 8.0 / took / 1e6,
            err * 100.0
        );
    }
    let _ = Command::new("ip").args(["link", "del", "ra"]).output();
}

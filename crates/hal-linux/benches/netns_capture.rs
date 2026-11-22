//! G6.4a — how many packets per second Torch's capture reads, with and
//! without the kernel's 1:N sampling, and what it costs in CPU, inside a
//! throwaway network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- \
//!     cargo bench -p corerouter-hal-linux --bench netns_capture
//! ```
//!
//! Sender threads write 64-byte UDP frames (256 flows) with `AF_PACKET`
//! into veth `cpa` as fast as they can; the capture (`HostCapture`, the
//! one Torch uses) listens on its peer `cpb` and decodes every frame it
//! reads, like Torch does. Per case it prints the rate the interface saw
//! (its own counter), the rate the capture read, the share, and the
//! capture thread's CPU (`/proc/thread-self/stat`). Not a criterion
//! group: the numbers are rates under load, not the time of one call.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("skipped: AF_PACKET is Linux-only");
}

#[cfg(target_os = "linux")]
fn main() {
    if !linux::ready() {
        return;
    }
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::os::fd::AsRawFd;
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use corerouter_hal::capture::{
        CaptureDevice, CaptureSpec, FrameBatch, HEADERS_SNAPLEN, PacketCapture, decode,
    };
    use corerouter_hal_linux::capture::HostCapture;
    use nix::ifaddrs::getifaddrs;
    use nix::sys::socket::{LinkAddr, MsgFlags, bind, send};
    use socket2::{Domain, Protocol, Socket, Type};

    const ENV: &str = "COREROUTER_NETNS_BENCH";
    const SECS: u64 = 3;

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
            "{ENV}=1 outside a fresh network namespace; refusing"
        );
        true
    }

    fn ip(args: &[&str]) {
        let out = Command::new("ip").args(args).output().unwrap();
        assert!(
            out.status.success(),
            "ip {args:?}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn link(name: &str) -> LinkAddr {
        getifaddrs()
            .unwrap()
            .filter(|a| a.interface_name == name)
            .find_map(|a| a.address.and_then(|s| s.as_link_addr().copied()))
            .unwrap()
    }

    fn frame(flow: u8) -> Vec<u8> {
        let mut f = vec![0x02, 0, 0, 0, 0, 0xBB, 0x02, 0, 0, 0, 0, 0xAA, 0x08, 0x00];
        f.extend_from_slice(&[0x45, 0, 0, 50, 0, 0, 0, 0, 64, 17, 0, 0]);
        f.extend_from_slice(&[10, 0, 0, flow, 10, 1, 0, 1]);
        f.extend_from_slice(&[0x13, 0x88, 0, 53, 0, 30, 0, 0]);
        f.resize(64, 0);
        f
    }

    fn rx_packets(dev: &str) -> u64 {
        let out = Command::new("ip")
            .args(["-s", "-j", "link", "show", dev])
            .output()
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        v[0]["stats64"]["rx"]["packets"].as_u64().unwrap()
    }

    /// CPU time of the calling thread (user + system).
    fn thread_cpu() -> Duration {
        let stat = std::fs::read_to_string("/proc/thread-self/stat").unwrap();
        let rest = stat.rsplit_once(')').unwrap().1;
        let f: Vec<&str> = rest.split_whitespace().collect();
        let ticks: u64 = f[11].parse::<u64>().unwrap() + f[12].parse::<u64>().unwrap();
        Duration::from_millis(ticks * 10)
    }

    fn case(name: &str, sample: u32, senders: usize) {
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();
        for t in 0..senders {
            let stop = Arc::clone(&stop);
            threads.push(std::thread::spawn(move || {
                let s = Socket::new(Domain::PACKET, Type::RAW, Some(Protocol::from(0))).unwrap();
                bind(s.as_raw_fd(), &link("cpa")).unwrap();
                let frames: Vec<Vec<u8>> = (0..=255u8).map(frame).collect();
                let mut i = t;
                while !stop.load(Ordering::Relaxed) {
                    let _ = send(s.as_raw_fd(), &frames[i % 256], MsgFlags::empty());
                    i += 1;
                }
            }));
        }
        std::thread::sleep(Duration::from_millis(300));
        let spec = CaptureSpec {
            devices: vec![CaptureDevice {
                name: "cpb".into(),
                vlan: None,
            }],
            snaplen: HEADERS_SNAPLEN,
            sample,
        };
        let mut sock = HostCapture.open(&spec).unwrap();
        let mut batch = FrameBatch::new(1024);
        let before = rx_packets("cpb");
        let cpu0 = thread_cpu();
        let t0 = Instant::now();
        let (mut read, mut decoded) = (0u64, 0u64);
        while t0.elapsed() < Duration::from_secs(SECS) {
            batch.clear();
            sock.recv(Duration::from_millis(100), &mut batch).unwrap();
            for (_, d) in batch.iter() {
                read += 1;
                if decode(d).is_some_and(|x| x.dst_port.is_some()) {
                    decoded += 1;
                }
            }
        }
        let secs = t0.elapsed().as_secs_f64();
        let cpu = thread_cpu().saturating_sub(cpu0).as_secs_f64() / secs * 100.0;
        let seen = rx_packets("cpb") - before;
        stop.store(true, Ordering::Relaxed);
        for t in threads {
            t.join().unwrap();
        }
        let offered = seen as f64 / secs;
        let got = read as f64 / secs * f64::from(sample);
        println!(
            "{name:<28} offered {:>7.0} kpps  read {:>7.0} kpps (x{sample} = {:>5.1} %)  capture CPU {cpu:>5.1} %  decoded {decoded}",
            offered / 1000.0,
            read as f64 / secs / 1000.0,
            got / offered.max(1.0) * 100.0,
        );
    }

    pub fn run() {
        ip(&["link", "add", "cpa", "type", "veth", "peer", "name", "cpb"]);
        ip(&["link", "set", "cpa", "up"]);
        ip(&["link", "set", "cpb", "up"]);
        let cpus = std::thread::available_parallelism().map_or(2, |n| n.get());
        let senders = (cpus / 4).clamp(1, 6);
        println!("netns_capture: veth, 64-byte UDP, {senders} sender thread(s), {SECS} s per case");
        case("1 sender, all frames", 1, 1);
        case("1 sender, 1:8 in the kernel", 8, 1);
        case(&format!("{senders} senders, all frames"), 1, senders);
        case(&format!("{senders} senders, 1:8 in the kernel"), 8, senders);
        case(
            &format!("{senders} senders, 1:64 in the kernel"),
            64,
            senders,
        );
    }
}

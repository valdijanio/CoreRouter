//! G1.27d: the neighbor tables read, watched and written for real, in a
//! throwaway network namespace, no root:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_neigh
//! ```
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::Write as _;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use corerouter_hal::Hal;
use corerouter_hal::neigh::{NeighEvent, NeighState, Neighbor, NeighborFeed};
use corerouter_hal_linux::LinuxHal;
use corerouter_model::arp::{ArpEntry, ArpInterface, ArpMode};
use corerouter_model::{AddressEntry, Config, IfName, Interface, InterfaceKind, ItemId, MacAddr};

const ENV: &str = "COREROUTER_NETNS_TESTS";
/// The tests share the namespace's tables: one at a time.
static ONE: Mutex<()> = Mutex::new(());

fn in_netns() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!(
            "skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net` (cargo xtask netns)"
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
        .map(|n| n.split('@').next().unwrap_or(n))
        .collect();
    assert!(
        names.iter().all(|n| *n == "lo" || n.starts_with("nb")),
        "{ENV}=1 but this namespace has {names:?}; refusing to touch it"
    );
    true
}

fn ip(args: &[&str]) -> String {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// `ip -batch -` with `lines`.
fn batch(lines: &str) {
    let mut child = Command::new("ip")
        .args(["-batch", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(lines.as_bytes())
        .unwrap();
    assert!(child.wait().unwrap().success());
}

/// A veth pair `<a>`/`<b>`, `a` with 10.<net>.0.1/16.
fn port(a: &str, b: &str, net: u8) {
    let _ = Command::new("ip").args(["link", "del", a]).output();
    ip(&["link", "add", a, "type", "veth", "peer", "name", b]);
    ip(&["addr", "add", &format!("10.{net}.0.1/16"), "dev", a]);
    ip(&["link", "set", a, "up"]);
    ip(&["link", "set", b, "up"]);
}

fn host(i: u32, net: u8) -> Ipv4Addr {
    Ipv4Addr::new(10, net, (2 + i / 250) as u8, (2 + i % 250) as u8)
}

fn on(port: &str, all: &[Neighbor]) -> Vec<Neighbor> {
    all.iter()
        .filter(|n| n.interface.as_str() == port)
        .cloned()
        .collect()
}

#[test]
fn thousands_of_neighbors_dump_with_their_states() {
    if !in_netns() {
        return;
    }
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    port("nba0", "nba1", 20);
    const N: u32 = 5000;
    let mut lines = String::new();
    // Learned entries count against gc_thresh3 (1024 by default, a
    // global of the first namespace): most are permanent (exempt).
    for i in 0..N {
        // 200 learned, far under gc_thresh3 (1024): a full table would
        // refuse the incomplete entry below ("neighbour table overflow").
        let state = match i % 50 {
            0 => "reachable",
            1 => "stale",
            _ => "permanent",
        };
        lines.push_str(&format!(
            "neigh replace {} lladdr 02:00:00:00:{:02x}:{:02x} dev nba0 nud {state}\n",
            host(i, 20),
            i / 256,
            i % 256
        ));
    }
    batch(&lines);
    let t = Instant::now();
    let all = LinuxHal::new().neighbors().unwrap();
    let took = t.elapsed();
    let mine = on("nba0", &all);
    eprintln!("dump of {} neighbors: {took:?}", all.len());
    // reachable ones may already have aged to stale; nothing else.
    assert_eq!(mine.len(), N as usize);
    assert!(mine.iter().all(|n| n.mac.is_some()));
    assert!(mine.iter().all(|n| matches!(
        n.state,
        NeighState::Reachable | NeighState::Stale | NeighState::Delay | NeighState::Permanent
    )));
    assert_eq!(
        mine.iter()
            .filter(|n| n.state == NeighState::Permanent)
            .count(),
        (N as usize) * 48 / 50
    );
    // An address nobody answers: the kernel asks, and the entry is
    // incomplete (RFC 4861 §7.3.2 INCOMPLETE; ARP the same in Linux).
    let s = UdpSocket::bind("10.20.0.1:0").unwrap();
    let lone: IpAddr = "10.20.255.250".parse().unwrap();
    let t = Instant::now();
    let n = loop {
        let _ = s.send_to(b"x", "10.20.255.250:9");
        if let Some(n) = LinuxHal::new()
            .neighbors()
            .unwrap()
            .into_iter()
            .find(|n| n.address == lone)
        {
            break n;
        }
        assert!(
            t.elapsed() < Duration::from_secs(3),
            "the kernel made no entry"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        matches!(n.state, NeighState::Incomplete | NeighState::Failed),
        "{n:?}"
    );
    assert_eq!(n.mac, None);
    ip(&["link", "del", "nba0"]);
}

#[test]
fn events_arrive_without_polling_and_flush_removes() {
    if !in_netns() {
        return;
    }
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    port("nbb0", "nbb1", 21);
    let mut hal = LinuxHal::new();
    let mut feed: Box<dyn NeighborFeed> = hal.neighbor_feed().unwrap();
    let mut first = Vec::new();
    assert!(feed.dump(&mut first).unwrap());
    let mut ev = Vec::new();
    feed.recv(0, 1000, &mut ev).unwrap();
    ev.clear();

    // Event latency: a change made now reaches the feed in…
    let mut worst = Duration::ZERO;
    for i in 0..50u32 {
        let a = host(i, 21);
        let t = Instant::now();
        ip(&[
            "neigh",
            "replace",
            &a.to_string(),
            "lladdr",
            "02:00:00:00:00:21",
            "dev",
            "nbb0",
            "nud",
            "reachable",
        ]);
        let spawned = t.elapsed();
        loop {
            feed.recv(1000, 64, &mut ev).unwrap();
            if ev
                .iter()
                .any(|e| matches!(e, NeighEvent::Upsert(n) if n.address == IpAddr::V4(a)))
            {
                break;
            }
            assert!(t.elapsed() < Duration::from_secs(5), "no event for {a}");
        }
        // The `ip` process itself is most of it; what is left is ours.
        worst = worst.max(t.elapsed().saturating_sub(spawned));
        ev.clear();
    }
    eprintln!("event → feed after the change returned: worst {worst:?} of 50");
    assert!(worst < Duration::from_millis(500));

    let items: Vec<(IfName, IpAddr)> = (0..50)
        .map(|i| ("nbb0".parse().unwrap(), IpAddr::V4(host(i, 21))))
        .collect();
    assert_eq!(hal.neighbor_remove(&items).unwrap(), 50);
    // Again: already gone is not an error.
    assert_eq!(hal.neighbor_remove(&items).unwrap(), 0);
    let mut gone = 0;
    let t = Instant::now();
    while gone < 50 && t.elapsed() < Duration::from_secs(5) {
        feed.recv(500, 256, &mut ev).unwrap();
        gone = ev
            .iter()
            .filter(|e| matches!(e, NeighEvent::Remove { .. }))
            .count();
    }
    assert_eq!(gone, 50);
    assert_eq!(feed.lost(), 0);
    ip(&["link", "del", "nbb0"]);
}

fn cfg(port: &str, net: u8) -> Config {
    let mut c = Config::default();
    let n: IfName = port.parse().unwrap();
    c.interfaces.insert(
        n.clone(),
        Interface::new(n.clone(), InterfaceKind::Ethernet),
    );
    c.ip.addresses.push(AddressEntry {
        id: ItemId(1),
        address: format!("10.{net}.0.1/16").parse().unwrap(),
        interface: n,
        disabled: false,
        comment: String::new(),
        from_pool: None,
    });
    c
}

fn sysctl(path: &str) -> String {
    std::fs::read_to_string(format!("/proc/sys/net/ipv4/{path}"))
        .unwrap()
        .trim()
        .to_owned()
}

#[test]
fn apply_writes_static_entries_and_modes_and_takes_them_back() {
    if !in_netns() {
        return;
    }
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    port("nbc0", "nbc1", 22);
    let base = cfg("nbc0", 22);
    let mut hal = LinuxHal::with_policy(corerouter_hal_linux::owner::Policy::default());
    hal.apply(&Config::default(), &base).unwrap();
    let n: IfName = "nbc0".parse().unwrap();
    let mut with = base.clone();
    with.ip.arp.entries.push(ArpEntry {
        id: ItemId(1),
        address: "10.22.0.50".parse().unwrap(),
        mac: MacAddr([2, 0, 0, 0, 0, 0x50]),
        interface: n.clone(),
        published: false,
        disabled: false,
        comment: String::new(),
    });
    with.ip.arp.set_interface(
        n.clone(),
        ArpInterface {
            mode: ArpMode::ProxyArp,
            timeout_secs: Some(120),
        },
    );
    hal.apply(&base, &with).unwrap();
    let shown = ip(&["neigh", "show", "10.22.0.50", "dev", "nbc0"]);
    assert!(
        shown.contains("02:00:00:00:00:50") && shown.contains("PERMANENT"),
        "{shown}"
    );
    assert_eq!(sysctl("conf/nbc0/proxy_arp"), "1");
    assert_eq!(sysctl("neigh/nbc0/base_reachable_time_ms"), "120000");

    // reply-only: no solicitations, so unknown hosts never resolve.
    let mut ro = with.clone();
    ro.ip.arp.set_interface(
        n.clone(),
        ArpInterface {
            mode: ArpMode::ReplyOnly,
            timeout_secs: None,
        },
    );
    hal.apply(&with, &ro).unwrap();
    assert_eq!(sysctl("conf/nbc0/proxy_arp"), "0");
    assert_eq!(sysctl("neigh/nbc0/mcast_solicit"), "0");
    assert_eq!(sysctl("neigh/nbc0/base_reachable_time_ms"), "30000");

    // disabled: IFF_NOARP.
    let mut off = ro.clone();
    off.ip.arp.set_interface(
        n.clone(),
        ArpInterface {
            mode: ArpMode::Disabled,
            timeout_secs: None,
        },
    );
    hal.apply(&ro, &off).unwrap();
    assert!(ip(&["link", "show", "nbc0"]).contains("NOARP"));

    // Back to the defaults: everything as the kernel had it.
    hal.apply(&off, &base).unwrap();
    assert!(!ip(&["link", "show", "nbc0"]).contains("NOARP"));
    assert_eq!(sysctl("neigh/nbc0/mcast_solicit"), "3");
    let shown = ip(&["neigh", "show", "10.22.0.50", "dev", "nbc0"]);
    assert!(!shown.contains("PERMANENT"), "{shown}");
    ip(&["link", "del", "nbc0"]);
}

/// A namespace of its own for the far end of a veth (a real host).
struct Ns(std::process::Child);

impl Ns {
    fn new() -> Self {
        let child = Command::new("unshare")
            .args(["--net", "--", "sleep", "600"])
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let ns = Ns(child);
        let mine = std::fs::read_link("/proc/self/ns/net").unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while std::fs::read_link(format!("/proc/{}/ns/net", ns.pid())).ok() == Some(mine.clone()) {
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
        let out = Command::new("nsenter")
            .args(["-t", pid.as_str(), "-n", "ip"])
            .args(args)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

impl Drop for Ns {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn arp_ping_gets_an_answer_from_a_real_host() {
    if !in_netns() {
        return;
    }
    let _one = ONE.lock().unwrap_or_else(|e| e.into_inner());
    let far = Ns::new();
    let _ = Command::new("ip").args(["link", "del", "nbd0"]).output();
    ip(&[
        "link",
        "add",
        "nbd0",
        "type",
        "veth",
        "peer",
        "name",
        "nbd1",
        "netns",
        &far.pid(),
    ]);
    ip(&["addr", "add", "10.23.0.1/16", "dev", "nbd0"]);
    ip(&["link", "set", "nbd0", "up"]);
    far.ip(&["addr", "add", "10.23.9.9/16", "dev", "nbd1"]);
    far.ip(&["link", "set", "nbd1", "up"]);
    let mut hal = LinuxHal::new();
    let mut p = hal.arp_pinger(&"nbd0".parse().unwrap()).unwrap();
    let mut rtts = Vec::new();
    for _ in 0..20 {
        let r = p
            .ping(
                Ipv4Addr::new(10, 23, 0, 1),
                Ipv4Addr::new(10, 23, 9, 9),
                Duration::from_secs(1),
            )
            .unwrap()
            .expect("the far host answers");
        rtts.push(r.rtt);
    }
    rtts.sort();
    eprintln!("ARP ping rtt: median {:?}, worst {:?}", rtts[10], rtts[19]);
    let silent = p
        .ping(
            Ipv4Addr::new(10, 23, 0, 1),
            Ipv4Addr::new(10, 23, 7, 7),
            Duration::from_millis(200),
        )
        .unwrap();
    assert_eq!(silent, None);
    // The far host is now a learned neighbor of ours (it asked back or
    // we resolved it): a real reachable entry with its MAC.
    let s = UdpSocket::bind("10.23.0.1:0").unwrap();
    let _ = s.send_to(b"x", "10.23.9.9:9");
    let t = Instant::now();
    let n = loop {
        let all = LinuxHal::new().neighbors().unwrap();
        if let Some(n) = all
            .into_iter()
            .find(|n| n.address == "10.23.9.9".parse::<IpAddr>().unwrap() && n.state.resolved())
        {
            break n;
        }
        assert!(t.elapsed() < Duration::from_secs(3), "never resolved");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(n.mac.is_some());
    ip(&["link", "del", "nbd0"]);
}

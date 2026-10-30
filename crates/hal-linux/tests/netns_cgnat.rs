//! CGNAT (G2.3) against a real kernel: subscribers in their own namespace
//! go out through this namespace's NAT to a server in a third one, which
//! checks each source address and port against the mapping formula —
//! no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_cgnat
//! ```
//!
//! ```text
//!  [subs ns] s0 ───veth─── i0  [this ns: the CGN]  e0 ───veth─── x0 [internet ns]
//!  100.64.0.1,.2,.65/24       100.64.0.254/24   192.0.2.1/24      192.0.2.2,.3/24
//!                              pool 203.0.113.0/30 (routed to 192.0.2.1 from x0)
//! ```
//!
//! Threads `setns` into the nested namespaces to open sockets there.
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use corerouter_hal::Hal;
use corerouter_hal::conntrack::status;
use corerouter_hal_linux::{LinuxHal, ctnl, nfnl, nft};
use corerouter_model::Config;
use corerouter_model::ItemId;
use corerouter_model::cgnat::{Exception, Pool};

const ENV: &str = "COREROUTER_NETNS_TESTS";

/// One lab at a time: the CGN table and the interface names are shared.
static KERNEL: Mutex<()> = Mutex::new(());

fn ready() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!("skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net`");
        return false;
    }
    // Checked once, before the first lab: a namespace with anything but
    // `lo` may be the host's, and this test adds veths and turns on
    // forwarding.
    static FRESH: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    let names = FRESH.get_or_init(|| {
        let text = run(Command::new("ip").args(["-o", "link", "show"]));
        text.lines()
            .filter_map(|l| l.split(':').nth(1))
            .map(|n| n.trim().to_owned())
            .collect()
    });
    assert!(
        names == &["lo"],
        "{ENV}=1 but this namespace has {names:?}; refusing to touch it"
    );
    if !nft::available() {
        eprintln!("skipped: the `nft` program (nftables) is not installed");
        return false;
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

fn ip(args: &[&str]) {
    run(Command::new("ip").args(args));
}

struct Ns(Child);

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
        ns.ip(&["link", "set", "lo", "up"]);
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

    fn sysctl(&self, path: &str, value: &str) {
        let pid = self.pid();
        let script = format!("echo '{value}' > /proc/sys/{path}");
        run(Command::new("nsenter").args(["-t", pid.as_str(), "-n", "sh", "-c", script.as_str()]));
    }

    /// Run `f` on a thread inside this namespace.
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

struct Lab {
    subs: Ns,
    net: Ns,
}

fn lab() -> Lab {
    let subs = Ns::new();
    let net = Ns::new();
    // The previous lab's veths die with its namespaces; make sure.
    for link in ["i0", "e0"] {
        let _ = Command::new("ip")
            .args(["link", "del", link])
            .stderr(Stdio::null())
            .status();
    }
    ip(&["link", "set", "lo", "up"]);
    ip(&[
        "link",
        "add",
        "i0",
        "type",
        "veth",
        "peer",
        "name",
        "s0",
        "netns",
        &subs.pid(),
    ]);
    ip(&[
        "link",
        "add",
        "e0",
        "type",
        "veth",
        "peer",
        "name",
        "x0",
        "netns",
        &net.pid(),
    ]);
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
    ip(&["addr", "add", "100.64.0.254/24", "dev", "i0"]);
    ip(&["addr", "add", "192.0.2.1/24", "dev", "e0"]);
    ip(&["link", "set", "i0", "up"]);
    ip(&["link", "set", "e0", "up"]);
    for a in ["100.64.0.1/24", "100.64.0.2/24", "100.64.0.65/24"] {
        subs.ip(&["addr", "add", a, "dev", "s0"]);
    }
    subs.ip(&["link", "set", "s0", "up"]);
    subs.ip(&["route", "add", "default", "via", "100.64.0.254"]);
    subs.sysctl("net/ipv4/ping_group_range", "0 0");
    for a in ["192.0.2.2/24", "192.0.2.3/24"] {
        net.ip(&["addr", "add", a, "dev", "x0"]);
    }
    net.ip(&["link", "set", "x0", "up"]);
    // The public pool and the 1:1 block are routed to the CGN, as an ISP's
    // upstream would.
    net.ip(&["route", "add", "203.0.113.0/30", "via", "192.0.2.1"]);
    net.ip(&["route", "add", "198.51.100.0/24", "via", "192.0.2.1"]);
    wait_active(None, "i0");
    wait_active(None, "e0");
    wait_active(Some(&subs), "s0");
    wait_active(Some(&net), "x0");
    Lab { subs, net }
}

/// Waits until `link` passes traffic. A veth gets its real qdisc in place
/// of the `noop` one, which drops every frame (`noop_enqueue`, counted in
/// TX dropped), only when the kernel's linkwatch work runs `dev_activate`
/// under the global `rtnl_lock` (net/core/link_watch.c, v7.0). With the
/// workspace's netns tests all running at once that came late, the first
/// ARP request of a test went nowhere, and the retry 1 s later
/// (`retrans_time_ms`) missed the 300 ms a test waits for its first
/// packet (flaked in the queue's batches).
fn wait_active(ns: Option<&Ns>, link: &str) {
    let start = Instant::now();
    loop {
        let mut c = match ns {
            Some(n) => {
                let mut c = Command::new("nsenter");
                c.args(["-t", n.pid().as_str(), "-n", "ip"]);
                c
            }
            None => Command::new("ip"),
        };
        let text = run(c.args(["-o", "link", "show", link]));
        if text.contains("state UP") && !text.contains("qdisc noop") {
            if start.elapsed() > Duration::from_secs(1) {
                eprintln!("{link} active after {:?}", start.elapsed());
            }
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "{link} still not active: {text}"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn pool(ports: u16) -> Pool {
    serde_json::from_value(serde_json::json!({
        "id": "*1", "name": "cgnat1", "inside": ["100.64.0.0/24"], "outside": ["203.0.113.0/30"],
        "ports_per_subscriber": ports,
    }))
    .unwrap()
}

fn cfg(p: Pool, exceptions: Vec<Exception>) -> Config {
    let mut c = Config::default();
    c.ip.cgnat.pools = vec![p];
    c.ip.cgnat.exceptions = exceptions;
    c
}

/// UDP from `from` (in the subscribers' namespace) to `to`; what the
/// server in the internet namespace saw as the source.
fn udp_seen(lab: &Lab, from: SocketAddrV4, to: SocketAddrV4) -> SocketAddrV4 {
    let server = lab.net.within(move || UdpSocket::bind(to).unwrap());
    server
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    lab.subs.within(move || {
        let s = UdpSocket::bind(from).unwrap();
        s.send_to(b"hi", to).unwrap();
    });
    let mut buf = [0u8; 16];
    let (_, src) = server
        .recv_from(&mut buf)
        .expect("the datagram crossed the NAT");
    match src {
        SocketAddr::V4(v4) => v4,
        SocketAddr::V6(_) => panic!("v6"),
    }
}

fn layout_of(p: &Pool) -> corerouter_model::cgnat::Layout {
    p.layout().unwrap()
}

#[test]
fn subscribers_leave_with_their_formula_address_and_ports() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let lab = lab();
    let p = pool(1000);
    let l = layout_of(&p);
    let ex = Exception {
        id: ItemId(2),
        subscriber: "100.64.0.2".parse().unwrap(),
        public: "198.51.100.9".parse().unwrap(),
        disabled: false,
        comment: String::new(),
    };
    let c = cfg(p, vec![ex]);
    let mut hal = LinuxHal::new();
    hal.apply(&Config::default(), &c).unwrap();

    // UDP: the address and port the server sees belong to the subscriber's
    // slot, and "who was" over them gives the subscriber back.
    let server = SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 7000);
    for (sub, sport) in [("100.64.0.1", 40000), ("100.64.0.65", 40001)] {
        let sub: Ipv4Addr = sub.parse().unwrap();
        let seen = udp_seen(&lab, SocketAddrV4::new(sub, sport), server);
        let slot = l.forward(sub).unwrap();
        assert!(
            slot.contains(*seen.ip(), seen.port()),
            "{sub}: {seen} outside {slot}"
        );
        assert_eq!(
            l.reverse(*seen.ip(), seen.port()),
            Some(sub),
            "who was {seen}"
        );
    }

    // The Connections window's view of it (G2.2): the kernel's table over
    // ctnetlink, with the translation and the table's size.
    let conns = hal.connections().unwrap();
    let udp = conns
        .iter()
        .find(|c| c.orig.src_port == 40000 && c.protocol == 17)
        .expect("the UDP connection is in the table");
    assert!(udp.has(status::SRC_NAT));
    assert!(l.forward("100.64.0.1".parse().unwrap()).unwrap().contains(
        match udp.reply.dst {
            std::net::IpAddr::V4(a) => a,
            std::net::IpAddr::V6(_) => panic!(),
        },
        udp.reply.dst_port
    ));
    let st = hal.connection_stats().unwrap();
    assert!(st.count >= 1 && st.max > 0, "{st:?}");

    // TCP from the same subscriber stays in the same slot (RFC 6888 REQ-2).
    let listener = lab
        .net
        .within(|| TcpListener::bind("192.0.2.2:8000").unwrap());
    let client = lab.subs.within(|| {
        let s = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None).unwrap();
        s.bind(&SocketAddr::from(([100, 64, 0, 65], 0)).into())
            .unwrap();
        s.connect_timeout(
            &SocketAddr::from(([192, 0, 2, 2], 8000)).into(),
            Duration::from_secs(3),
        )
        .unwrap();
        TcpStream::from(s)
    });
    let (mut conn, peer) = listener.accept().unwrap();
    let SocketAddr::V4(peer) = peer else { panic!() };
    let slot = l.forward("100.64.0.65".parse().unwrap()).unwrap();
    assert!(
        slot.contains(*peer.ip(), peer.port()),
        "tcp {peer} outside {slot}"
    );
    conn.write_all(b"ok").unwrap();
    let mut buf = [0u8; 2];
    (&client).read_exact(&mut buf).unwrap();

    // ICMP echo: the query id is rewritten into the same range (RFC 5508
    // §3.1; the kernel applies the snat range to ids).
    let raw = lab.net.within(|| {
        let s = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )
        .unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s
    });
    lab.subs.within(|| {
        let s = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::ICMPV4),
        )
        .unwrap();
        s.bind(&SocketAddr::from(([100, 64, 0, 1], 0)).into())
            .unwrap();
        // Echo request, id 0 (the ping socket picks one), seq 1.
        let pkt = [8u8, 0, 0, 0, 0, 0, 0, 1, b'c', b'g'];
        s.send_to(&pkt, &SocketAddr::from(([192, 0, 2, 2], 0)).into())
            .unwrap();
    });
    let slot = l.forward("100.64.0.1".parse().unwrap()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut found = None;
    while found.is_none() && Instant::now() < deadline {
        let mut buf = [0u8; 256];
        let Ok(n) = (&raw).read(&mut buf) else { break };
        let bytes = &buf[..n];
        let ihl = usize::from(bytes[0] & 0x0f) * 4;
        let src = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
        if bytes.get(ihl) == Some(&8) {
            let id = u16::from_be_bytes([bytes[ihl + 4], bytes[ihl + 5]]);
            found = Some((src, id));
        }
    }
    let (src, id) = found.expect("the echo request reached the server");
    assert!(slot.contains(src, id), "icmp {src} id {id} outside {slot}");

    // The 1:1 exception: its own address, its port kept.
    let seen = udp_seen(
        &lab,
        SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 2), 40002),
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 7001),
    );
    assert_eq!(
        seen,
        SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 9), 40002)
    );

    // Unclaimed packets to the pool are dropped, not routed back. And `nft`
    // reads what netlink loaded as we print it: one rule for every
    // protocol, ranged map data.
    let text = run(Command::new("nft").args(["list", "table", "ip", "corerouter_cgnat"]));
    assert!(text.contains("counter packets 0"), "{text}");
    assert!(
        text.contains("type ipv4_addr : interval ipv4_addr . inet_service"),
        "{text}"
    );
    assert!(text.contains("snat ip to ip saddr map @d_1"), "{text}");
    assert!(
        text.contains("100.64.0.65 : 203.0.113.1 . 2024-3023"),
        "{text}"
    );

    // Removing the pools removes the table.
    hal.apply(&c, &Config::default()).unwrap();
    let out = Command::new("nft")
        .args(["list", "table", "ip", "corerouter_cgnat"])
        .output()
        .unwrap();
    assert!(!out.status.success(), "the table is gone");
    drop(client);
}

#[test]
fn eim_eif_and_hairpin() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let lab = lab();
    let mut p = pool(1000);
    p.endpoint_independent_filtering = true;
    let c = cfg(p.clone(), vec![]);
    let mut hal = LinuxHal::new();
    hal.apply(&Config::default(), &c).unwrap();
    // The subscriber talks to server A...
    let sub = lab
        .subs
        .within(|| UdpSocket::bind("100.64.0.1:41000").unwrap());
    sub.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let a = lab
        .net
        .within(|| UdpSocket::bind("192.0.2.2:7100").unwrap());
    a.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    sub.send_to(b"to-a", "192.0.2.2:7100").unwrap();
    let mut buf = [0u8; 16];
    let (_, mapped) = a.recv_from(&mut buf).unwrap();
    // ...then to server B from the same port: the same public port (EIM,
    // RFC 4787 REQ-1).
    let b = lab
        .net
        .within(|| UdpSocket::bind("192.0.2.3:7200").unwrap());
    b.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    sub.send_to(b"to-b", "192.0.2.3:7200").unwrap();
    let (_, mapped_b) = b.recv_from(&mut buf).unwrap();
    assert_eq!(mapped, mapped_b, "endpoint-independent mapping");
    // A host it never talked to reaches it (EIF, REQ-8).
    let c3 = lab
        .net
        .within(|| UdpSocket::bind("192.0.2.3:7300").unwrap());
    c3.send_to(b"hello", mapped).unwrap();
    let (n, from) = sub.recv_from(&mut buf).expect("EIF lets the stranger in");
    assert_eq!(&buf[..n], b"hello");
    assert_eq!(from, "192.0.2.3:7300".parse::<SocketAddr>().unwrap());
    // Hairpin (REQ-9): another subscriber reaches it through the public
    // address and port, and is seen with its own public address.
    let other = lab
        .subs
        .within(|| UdpSocket::bind("100.64.0.65:42000").unwrap());
    other.send_to(b"hairpin", mapped).unwrap();
    let (n, from) = sub.recv_from(&mut buf).expect("hairpinned");
    assert_eq!(&buf[..n], b"hairpin");
    let SocketAddr::V4(from) = from else { panic!() };
    let slot = layout_of(&p)
        .forward("100.64.0.65".parse().unwrap())
        .unwrap();
    assert!(
        slot.contains(*from.ip(), from.port()),
        "hairpin source {from} is the public one"
    );
    hal.apply(&c, &Config::default()).unwrap();
}

fn map_text(name: &str) -> String {
    run(Command::new("nft").args(["list", "map", "ip", "corerouter_cgnat", name]))
}

/// Live connections from `sub`:`port` that went through the NAT.
fn nat_conns(sub: &str, port: u16) -> usize {
    let sub: std::net::IpAddr = sub.parse().unwrap();
    ctnl::dump()
        .unwrap()
        .iter()
        .filter(|c| c.orig.src == sub && c.orig.src_port == port && c.has(status::SRC_NAT))
        .count()
}

#[test]
fn element_changes_go_incremental_and_remaps_kill_connections() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let lab = lab();
    let mut small = pool(1000);
    small.inside = vec!["100.64.0.0/26".parse().unwrap()];
    let a = cfg(small, vec![]);
    let mut hal = LinuxHal::new();
    hal.apply(&Config::default(), &a).unwrap();
    let seen = udp_seen(
        &lab,
        SocketAddrV4::new(Ipv4Addr::new(100, 64, 0, 1), 45000),
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 2), 7500),
    );
    assert!(
        map_text("eim_1").contains(&format!("{} . {}", seen.ip(), seen.port())),
        "{}",
        map_text("eim_1")
    );
    assert_eq!(nat_conns("100.64.0.1", 45000), 1);

    // More subscribers: only elements change, so the live UDP mapping and
    // the connection survive (.1 keeps its slot).
    let b = cfg(pool(1000), vec![]);
    hal.apply(&a, &b).unwrap();
    assert!(map_text("d_1").contains("100.64.0.200"), "grown");
    assert!(
        map_text("eim_1").contains(&format!("{} . {}", seen.ip(), seen.port())),
        "kept"
    );
    assert_eq!(nat_conns("100.64.0.1", 45000), 1);

    // Other ports per subscriber remap everyone: their connections and
    // UDP mappings go, so "who was" names who the new formula names.
    let mut p = pool(500);
    p.inside = vec!["100.64.0.0/24".parse().unwrap()];
    let c = cfg(p, vec![]);
    hal.apply(&b, &c).unwrap();
    assert_eq!(nat_conns("100.64.0.1", 45000), 0, "killed");
    assert!(
        !map_text("eim_1").contains("elements"),
        "{}",
        map_text("eim_1")
    );
    hal.apply(&c, &Config::default()).unwrap();
}

#[test]
fn a_refused_batch_changes_nothing() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let c = cfg(pool(1000), vec![]);
    let mut hal = LinuxHal::new();
    hal.apply(&Config::default(), &c).unwrap();
    let before = map_text("d_1");
    // A rule naming a set that does not exist: the kernel refuses the
    // batch, after the delete of the table in it.
    let mut bad = corerouter_firewall::cgnat::table(&c.ip.cgnat).unwrap();
    if let Some(r) = bad.rules.first_mut() {
        r.exprs.insert(
            1,
            corerouter_firewall::program::Expr::Lookup {
                set: "nope".into(),
                sreg: corerouter_firewall::program::REG_1,
                dreg: None,
                inv: false,
            },
        );
    }
    let err = nfnl::apply(nfnl::replace(&bad, 1), "test").unwrap_err();
    assert!(err.to_string().contains("nothing changed"), "{err}");
    assert_eq!(map_text("d_1"), before, "the old table is intact");
    hal.apply(&c, &Config::default()).unwrap();
}

/// Blocks mode (G2.3c): the first packet of a subscriber without a block
/// waits in the netfilter queue. With nobody serving the queue it is
/// dropped (never let out untranslated); served, the block is put in the
/// map and the packet leaves inside it; a replace of the table keeps it.
#[test]
fn blocks_mode_holds_the_first_packet_until_a_block_is_given() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let lab = lab();
    let mut p = pool(1000);
    p.mode = corerouter_model::cgnat::Mode::Blocks;
    p.endpoint_independent_mapping = false;
    let l = p.layout().unwrap();
    let c = cfg(p.clone(), vec![]);
    let hal = std::sync::Arc::new(std::sync::Mutex::new(LinuxHal::new()));
    hal.lock().unwrap().apply(&Config::default(), &c).unwrap();
    let text = run(Command::new("nft").args(["list", "chain", "ip", "corerouter_cgnat", "blocks"]));
    assert!(
        text.contains("queue to 7422") || text.contains("queue num 7422"),
        "{text}"
    );

    // Nobody serves the queue: the packet is dropped.
    let server = lab
        .net
        .within(|| UdpSocket::bind("192.0.2.2:7700").unwrap());
    server
        .set_read_timeout(Some(Duration::from_millis(800)))
        .unwrap();
    lab.subs.within(|| {
        UdpSocket::bind("100.64.0.65:43000")
            .unwrap()
            .send_to(b"x", "192.0.2.2:7700")
            .unwrap();
    });
    let mut buf = [0u8; 8];
    assert!(
        server.recv_from(&mut buf).is_err(),
        "no block, no listener: dropped, not leaked"
    );

    // Serve it: allocate block 3 of the first public address.
    let mut q = hal.lock().unwrap().cgnat_queue().unwrap();
    let slot = l.block(0, 3).unwrap();
    let h2 = hal.clone();
    let serving = std::thread::spawn(move || {
        let pending = loop {
            if let Some(p) = q.recv(Duration::from_secs(5)).unwrap() {
                break p;
            }
        };
        h2.lock()
            .unwrap()
            .cgnat_blocks(&[corerouter_hal::cgnat::BlockChange {
                pool: ItemId(1),
                subscriber: pending.subscriber,
                slot: Some(slot),
            }])
            .unwrap();
        q.verdict(pending.id, true).unwrap();
        pending.subscriber
    });
    lab.subs.within(|| {
        UdpSocket::bind("100.64.0.65:43001")
            .unwrap()
            .send_to(b"y", "192.0.2.2:7700")
            .unwrap();
    });
    let (_, seen) = server.recv_from(&mut buf).expect("the held packet went on");
    assert_eq!(serving.join().unwrap(), Ipv4Addr::new(100, 64, 0, 65));
    let SocketAddr::V4(seen) = seen else { panic!() };
    assert!(
        slot.contains(*seen.ip(), seen.port()),
        "{seen} outside {slot}"
    );

    // A change that rebuilds the table (an exception adds maps) keeps the
    // block in the map.
    let ex = Exception {
        id: ItemId(9),
        subscriber: "100.64.0.9".parse().unwrap(),
        public: "198.51.100.9".parse().unwrap(),
        disabled: false,
        comment: String::new(),
    };
    let c2 = cfg(p, vec![ex]);
    hal.lock().unwrap().apply(&c, &c2).unwrap();
    assert!(
        map_text("d_1").contains("100.64.0.65 : 203.0.113.0 . 4024-5023"),
        "{}",
        map_text("d_1")
    );
    hal.lock().unwrap().apply(&c2, &Config::default()).unwrap();
}

/// Port exhaustion (RFC 6888 REQ-3, REQ-11): a subscriber with 64 ports
/// that opens 80 flows to the same server gets at most 64 through, every
/// one inside its own slot — it never borrows a neighbour's port — and the
/// kernel counts the refused ones (what the engine's alerts read).
#[test]
fn a_subscriber_out_of_ports_never_borrows_another_s() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let lab = lab();
    let p = pool(64);
    let c = cfg(p.clone(), vec![]);
    let mut hal = LinuxHal::new();
    hal.apply(&Config::default(), &c).unwrap();
    let before = hal.connection_stats().unwrap();
    let server = lab
        .net
        .within(|| UdpSocket::bind("192.0.2.2:7600").unwrap());
    // 80 sockets, each its own flow (another local port).
    let sockets: Vec<UdpSocket> = lab.subs.within(|| {
        (0..80)
            .map(|_| {
                let s = UdpSocket::bind("100.64.0.1:0").unwrap();
                s.send_to(b"x", "192.0.2.2:7600").unwrap();
                s
            })
            .collect()
    });
    let mut seen = std::collections::BTreeSet::new();
    let mut buf = [0u8; 8];
    for (_, from) in burst(&server, &mut buf, 64) {
        seen.insert(from);
    }
    let slot = layout_of(&p)
        .forward("100.64.0.1".parse().unwrap())
        .unwrap();
    assert!(
        !seen.is_empty() && seen.len() <= 64,
        "{} flows through",
        seen.len()
    );
    for from in &seen {
        let SocketAddr::V4(v4) = from else { panic!() };
        assert!(
            slot.contains(*v4.ip(), v4.port()),
            "{from} outside the slot {slot:?}"
        );
    }
    let after = hal.connection_stats().unwrap();
    let refused =
        (after.insert_failed + after.drop).saturating_sub(before.insert_failed + before.drop);
    eprintln!(
        "{} of 80 flows through, {refused} refused by the kernel",
        seen.len()
    );
    assert_eq!(seen.len(), 64, "the whole slot, no more");
    assert!(refused > 0, "the kernel counted the refused flows");
    drop(sockets);
    hal.apply(&c, &Config::default()).unwrap();
}

/// The datagrams of a burst that should bring `expect`: up to 3 s for
/// each until they are in, then 300 ms more for any extra. One 300 ms
/// wait for all lost the burst on a loaded machine: the first packet of a
/// flow (the ruleset, an ARP) or a pause in the middle took longer
/// (flaked in the queue's batches).
fn burst(server: &UdpSocket, buf: &mut [u8], expect: usize) -> Vec<(usize, SocketAddr)> {
    let mut got = Vec::new();
    loop {
        let wait = if got.len() < expect {
            Duration::from_secs(3)
        } else {
            Duration::from_millis(300)
        };
        server.set_read_timeout(Some(wait)).unwrap();
        match server.recv_from(buf) {
            Ok(r) => got.push(r),
            Err(_) => return got,
        }
    }
}

/// Serve the exhaustion queues of `hal` on a thread until `stop`.
fn serve_exhaustion(
    hal: &mut LinuxHal,
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> std::thread::JoinHandle<usize> {
    let mut queues: Vec<_> = (0..corerouter_hal::cgnat::EXHAUSTED_QUEUES)
        .map(|i| hal.cgnat_exhaustion_queue(i).unwrap())
        .collect();
    std::thread::spawn(move || {
        let mut n = 0;
        while !stop.load(std::sync::atomic::Ordering::Relaxed) {
            for q in &mut queues {
                n += q.serve(Duration::from_millis(5)).unwrap();
            }
        }
        n
    })
}

/// A raw ICMP socket in the subscribers' namespace (as a `UdpSocket`, whose
/// `recv` reads any datagram socket safely).
fn icmp_listener(lab: &Lab) -> UdpSocket {
    lab.subs.within(|| {
        let s = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )
        .unwrap();
        UdpSocket::from(s)
    })
}

/// The ICMP unreachable messages `sock` sees within `wait`: (code, quoted
/// source address, quoted source port, when).
fn icmp_seen(sock: &UdpSocket, wait: Duration) -> Vec<(u8, Ipv4Addr, u16, Instant)> {
    let mut out = Vec::new();
    let deadline = Instant::now() + wait;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
        sock.set_read_timeout(Some(left.max(Duration::from_millis(1))))
            .unwrap();
        let mut b = [0u8; 1500];
        let Ok(n) = sock.recv(&mut b) else { break };
        let at = Instant::now();
        let b = &b[..n];
        let ihl = usize::from(b[0] & 0x0f) * 4;
        let icmp = &b[ihl..];
        if icmp[0] != 3 {
            continue;
        }
        let q = &icmp[8..];
        let qihl = usize::from(q[0] & 0x0f) * 4;
        out.push((
            icmp[1],
            Ipv4Addr::new(q[12], q[13], q[14], q[15]),
            u16::from_be_bytes([q[qihl], q[qihl + 1]]),
            at,
        ));
    }
    out
}

/// G2.7, RFC 6888 REQ-11: a subscriber out of ports gets an ICMP host
/// unreachable (code 1) quoting the datagram as it sent it (private
/// address and port), at most the configured rate; a nearly full
/// subscriber with ports left goes out as before; a subscriber not in the
/// set never reaches the queue.
#[test]
fn a_subscriber_out_of_ports_gets_icmp_host_unreachable() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let lab = lab();
    let mut p = pool(64);
    p.endpoint_independent_mapping = false;
    let mut c = cfg(p.clone(), vec![]);
    c.ip.cgnat.settings.icmp_rate = 5;
    let mut hal = LinuxHal::new();
    hal.apply(&Config::default(), &c).unwrap();
    let text =
        run(Command::new("nft").args(["list", "chain", "ip", "corerouter_cgnat", "exhausted"]));
    assert!(text.contains("@full") && text.contains("bypass"), "{text}");

    let server = lab
        .net
        .within(|| UdpSocket::bind("192.0.2.2:7600").unwrap());
    // .1 takes its 64 ports to one destination.
    let sockets: Vec<UdpSocket> = lab.subs.within(|| {
        (0..64)
            .map(|_| {
                let s = UdpSocket::bind("100.64.0.1:0").unwrap();
                s.send_to(b"x", "192.0.2.2:7600").unwrap();
                s
            })
            .collect()
    });
    let mut buf = [0u8; 8];
    let through = burst(&server, &mut buf, 64).len();
    assert_eq!(through, 64);

    let a: Ipv4Addr = "100.64.0.1".parse().unwrap();
    let b: Ipv4Addr = "100.64.0.2".parse().unwrap();
    hal.cgnat_full(&[a, b]).unwrap();
    let full = run(Command::new("nft").args(["list", "set", "ip", "corerouter_cgnat", "full"]));
    assert!(full.contains("100.64.0.1"), "{full}");
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let serving = serve_exhaustion(&mut hal, stop.clone());
    let icmp = icmp_listener(&lab);

    // Ten more flows from .1: dropped, and ICMP code 1 about each, up to
    // the rate (5 per second, burst 5).
    let sent = Instant::now();
    let ports: Vec<u16> = lab.subs.within(|| {
        (0..10)
            .map(|_| {
                let s = UdpSocket::bind("100.64.0.1:0").unwrap();
                s.send_to(b"y", "192.0.2.2:7600").unwrap();
                s.local_addr().unwrap().port()
            })
            .collect()
    });
    let seen = icmp_seen(&icmp, Duration::from_millis(600));
    assert!(
        server.recv_from(&mut buf).is_err(),
        "nothing more got through"
    );
    // The burst, and what the bucket refills while the ten are refused: on
    // a loaded machine they spread over more than 200 ms, one more token
    // (flaked in the queue's batches). Unlimited would be ten at once.
    let spread = match (
        seen.iter().map(|s| s.3).min(),
        seen.iter().map(|s| s.3).max(),
    ) {
        (Some(a), Some(b)) => b.duration_since(a),
        _ => Duration::ZERO,
    };
    let allowed = 5 + (spread.as_secs_f64() * 5.0).ceil() as usize;
    assert!(
        (5..=allowed).contains(&seen.len()),
        "the burst, no more ({allowed} in {spread:?}): {seen:?}"
    );
    for (code, src, port, _) in &seen {
        assert_eq!(*code, 1, "host unreachable (RFC 6888 REQ-11b)");
        assert_eq!(*src, a, "the private source, as sent");
        assert!(ports.contains(port), "the subscriber's own port {port}");
    }
    let first = seen.iter().map(|s| s.3).min().unwrap();
    eprintln!(
        "first ICMP {:?} after the datagram",
        first.duration_since(sent)
    );

    // .2 is in the set but has ports: it goes out, no ICMP.
    let seen_b = udp_seen(
        &lab,
        "100.64.0.2:41000".parse().unwrap(),
        "192.0.2.2:7601".parse().unwrap(),
    );
    assert!(
        layout_of(&p)
            .forward(b)
            .unwrap()
            .contains(*seen_b.ip(), seen_b.port())
    );
    // .65 is not in the set: never queued.
    udp_seen(
        &lab,
        "100.64.0.65:41000".parse().unwrap(),
        "192.0.2.2:7602".parse().unwrap(),
    );
    assert!(icmp_seen(&icmp, Duration::from_millis(200)).is_empty());

    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let served = serving.join().unwrap();
    let (hits, stats) = hal.cgnat_exhausted();
    eprintln!("served {served}, {stats:?}");
    assert_eq!(served, 11, "ten from .1 and one from .2; .65 never");
    assert_eq!(stats.refused, 10);
    assert_eq!(stats.icmp, seen.len() as u64);
    assert_eq!(stats.limited, 10 - seen.len() as u64);
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].0, a);
    drop(sockets);
    hal.apply(&c, &Config::default()).unwrap();
}

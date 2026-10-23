//! The fast path (G2.4) against a real kernel: a subscriber's TCP
//! connection goes out through the CGNAT and, once established, into the
//! software flowtable (conntrack marks it `OFFLOAD`); hardware offload on
//! a veth is refused, `auto` falls back to software and `yes` refuses the
//! change. No root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_fastpath
//! ```
//!
//! Same topology as `netns_cgnat`: subscribers ─ i0 [this ns] e0 ─ internet.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use corerouter_hal::Hal;
use corerouter_hal::conntrack::status;
use corerouter_hal_linux::{LinuxHal, ctnl, nft};
use corerouter_model::Config;
use corerouter_model::cgnat::Pool;
use corerouter_model::fastpath::HwOffload;

const ENV: &str = "COREROUTER_NETNS_TESTS";

/// One lab at a time: the tables and the interface names are shared.
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
    Lab { subs, net }
}

fn cfg(hw: HwOffload) -> Config {
    let mut c = Config::default();
    let p: Pool = serde_json::from_value(serde_json::json!({
        "id": "*1", "name": "cgnat1", "inside": ["100.64.0.0/24"], "outside": ["203.0.113.0/30"],
    }))
    .unwrap();
    c.ip.cgnat.pools = vec![p];
    c.ip.fastpath.enabled = true;
    c.ip.fastpath.interfaces = vec!["i0".parse().unwrap(), "e0".parse().unwrap()];
    c.ip.fastpath.hw_offload = hw;
    c
}

/// A TCP exchange subscriber 100.64.0.1 → 192.0.2.2:8080, left open.
fn tcp_session(lab: &Lab) -> (TcpStream, std::thread::JoinHandle<()>) {
    let listener = lab
        .net
        .within(|| TcpListener::bind("192.0.2.2:8080").unwrap());
    let server = std::thread::spawn(move || {
        let (mut c, _) = listener.accept().unwrap();
        let mut buf = [0u8; 64];
        // Echo until the client closes.
        while let Ok(n) = c.read(&mut buf) {
            if n == 0 || c.write_all(&buf[..n]).is_err() {
                break;
            }
        }
    });
    let mut client = lab.subs.within(|| {
        TcpStream::connect_timeout(&"192.0.2.2:8080".parse().unwrap(), Duration::from_secs(3))
            .unwrap()
    });
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    for i in 0..20u8 {
        client.write_all(&[i; 32]).unwrap();
        let mut back = [0u8; 32];
        client.read_exact(&mut back).unwrap();
        assert_eq!(back, [i; 32]);
    }
    (client, server)
}

fn table_text() -> Option<String> {
    let out = Command::new("nft")
        .args(["list", "table", "inet", "corerouter_fastpath"])
        .output()
        .unwrap();
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn established_connections_enter_the_flowtable_with_their_nat() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let lab = lab();
    let mut hal = LinuxHal::new();
    // auto on veths: the kernel refuses `flags offload`, software follows.
    let c = cfg(HwOffload::Auto);
    hal.apply(&Config::default(), &c).unwrap();
    let st = hal.fastpath_state();
    assert!(st.active && !st.hardware, "{st:?}");
    assert!(
        st.note
            .as_deref()
            .unwrap_or("")
            .contains("running in software"),
        "{st:?}"
    );
    assert_eq!(st.devices, ["i0", "e0"]);
    // nft reads back what we sent over netlink.
    let text = table_text().expect("the table is in the kernel");
    assert!(text.contains("flowtable ft"), "{text}");
    assert!(
        text.contains("devices = { e0, i0 }") || text.contains("devices = { i0, e0 }"),
        "{text}"
    );
    assert!(text.contains("flow add @ft"), "{text}");

    let (client, server) = tcp_session(&lab);
    let conns = ctnl::dump().unwrap();
    let mine: Vec<_> = conns
        .iter()
        .filter(|c| c.orig.src.to_string() == "100.64.0.1" && c.orig.dst_port == 8080)
        .collect();
    assert_eq!(mine.len(), 1, "{conns:?}");
    assert!(mine[0].has(status::SRC_NAT), "translated by the CGNAT");
    assert!(
        mine[0].has(status::OFFLOAD),
        "in the flowtable: {:?}",
        mine[0]
    );
    assert!(!mine[0].has(status::HW_OFFLOAD), "a veth has no hardware");
    drop(client);
    server.join().unwrap();

    // hw_offload=yes: refused whole; the software flowtable stays.
    let yes = cfg(HwOffload::Yes);
    let e = hal.apply(&c, &yes).unwrap_err().to_string();
    assert!(e.contains("hardware offload is required"), "{e}");
    assert!(hal.fastpath_state().active);
    assert!(table_text().is_some());

    // Off: the table goes.
    hal.apply(&c, &Config::default()).unwrap();
    assert!(!hal.fastpath_state().active);
    assert!(table_text().is_none(), "table removed");
}

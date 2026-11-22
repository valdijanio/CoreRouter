//! G4.10b: the subscriber notices' chains against a real kernel, inside a
//! throwaway network namespace — no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_notice
//! ```
//!
//! ```text
//!  [subscriber ns] sa 100.64.0.10 ─veth─ ra 100.64.0.1 [router: this ns] ri 198.51.100.254 (dummy: "internet")
//! ```
//!
//! The router listens on the portal's port; the subscriber connects to a
//! site behind the dummy (where nothing answers): port 80 must reach the
//! portal, 443 must be refused at once (block), and a subscriber outside
//! the list must reach neither.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use corerouter_hal::{DynamicChange, Hal};
use corerouter_hal_linux::{LinuxHal, Policy, nft};
use corerouter_model::firewall::{AddrMatch, DynamicAddress};
use corerouter_model::subscriber_notice::{Mode, Profile};
use corerouter_model::{Config, ItemId};

const ENV: &str = "COREROUTER_NETNS_TESTS";
const PORT: u16 = 8880;

fn ready() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!("skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net`");
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
    assert!(
        names == ["lo"],
        "{ENV}=1 but this namespace has {names:?}; refusing to touch it"
    );
    if !nft::available() {
        eprintln!("skipped: the `nft` program (nftables) is not installed");
        return false;
    }
    true
}

fn run(cmd: &mut Command) {
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{cmd:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn ip(args: &[&str]) {
    run(Command::new("ip").args(args));
}

/// The subscriber's namespace (a child `unshare --net`).
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

/// What a TCP connect from the subscriber to `dst` gives, and how fast.
#[derive(Debug, PartialEq)]
enum Got {
    Connected,
    Refused,
    TimedOut,
}

fn try_connect(sub: &Ns, dst: &str) -> (Got, Duration) {
    let dst: SocketAddr = dst.parse().unwrap();
    sub.within(move || {
        let start = Instant::now();
        let got = match TcpStream::connect_timeout(&dst, Duration::from_millis(800)) {
            Ok(mut s) => {
                let _ = s.write_all(
                    b"GET /generate_204 HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\n\r\n",
                );
                Got::Connected
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => Got::Refused,
            Err(_) => Got::TimedOut,
        };
        (got, start.elapsed())
    })
}

fn profile(mode: Mode) -> Config {
    let mut c = Config::default();
    c.ip.subscriber_notice.profiles.push(Profile::new(
        ItemId(1),
        "atraso".parse().unwrap(),
        mode,
        "bloqueados".parse().unwrap(),
    ));
    c
}

fn member(hal: &mut LinuxHal, list: &str, add: bool) {
    let d = DynamicAddress {
        list: list.parse().unwrap(),
        address: AddrMatch::Net("100.64.0.10/32".parse().unwrap()),
        timeout_secs: 600,
        added_by_rule: false,
    };
    let c = if add {
        DynamicChange::Add(&d)
    } else {
        DynamicChange::Remove(&d)
    };
    hal.address_list_dynamic(c).unwrap();
}

#[test]
fn block_redirects_http_refuses_the_rest_and_lets_go() {
    if !ready() {
        return;
    }
    let sub = Ns::new();
    ip(&["link", "set", "lo", "up"]);
    ip(&[
        "link",
        "add",
        "ra",
        "type",
        "veth",
        "peer",
        "name",
        "sa",
        "netns",
        &sub.pid(),
    ]);
    ip(&["link", "add", "ri", "type", "dummy"]);
    for d in ["ra", "ri"] {
        ip(&["link", "set", d, "up"]);
    }
    ip(&["addr", "add", "100.64.0.1/24", "dev", "ra"]);
    ip(&["addr", "add", "198.51.100.254/24", "dev", "ri"]);
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1").unwrap();
    sub.ip(&["link", "set", "lo", "up"]);
    sub.ip(&["addr", "add", "100.64.0.10/24", "dev", "sa"]);
    sub.ip(&["link", "set", "sa", "up"]);
    sub.ip(&["route", "add", "default", "via", "100.64.0.1"]);
    // A neighbor that never answers: packets to the "site" vanish (a
    // connect times out unless something refuses or redirects it).
    ip(&[
        "neigh",
        "replace",
        "198.51.100.7",
        "lladdr",
        "02:00:00:00:00:07",
        "dev",
        "ri",
        "nud",
        "permanent",
    ]);

    let portal = TcpListener::bind(("0.0.0.0", PORT)).unwrap();
    portal.set_nonblocking(true).unwrap();
    let mut hal = LinuxHal::with_policy(Policy {
        manage: vec!["ra".into(), "ri".into()],
        unmanaged: Vec::new(),
    });
    let cfg = profile(Mode::Block);
    hal.apply(&Config::default(), &cfg).unwrap();

    // Outside the list: untouched (the site does not answer).
    let (got, _) = try_connect(&sub, "198.51.100.7:80");
    assert_eq!(got, Got::TimedOut, "a non-member is not redirected");

    // In the list: port 80 reaches the portal, 443 is refused at once.
    member(&mut hal, "bloqueados", true);
    let (got, _) = try_connect(&sub, "198.51.100.7:80");
    assert_eq!(got, Got::Connected, "port 80 goes to the portal");
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut head = Vec::new();
    while Instant::now() < deadline {
        if let Ok((mut c, from)) = portal.accept() {
            assert_eq!(
                from.ip().to_string(),
                "100.64.0.10",
                "the subscriber's own address reaches the portal"
            );
            c.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let mut buf = [0u8; 512];
            let n = c.read(&mut buf).unwrap_or(0);
            head.extend_from_slice(&buf[..n]);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        String::from_utf8_lossy(&head).contains("connectivitycheck.gstatic.com"),
        "the probe arrived"
    );
    let (got, took) = try_connect(&sub, "198.51.100.7:443");
    assert_eq!(got, Got::Refused, "HTTPS refused");
    assert!(
        took < Duration::from_millis(200),
        "refused at once, not hanging: {took:?}"
    );

    // Out of the list again: released on the next packet.
    let start = Instant::now();
    member(&mut hal, "bloqueados", false);
    let release = start.elapsed();
    let (got, _) = try_connect(&sub, "198.51.100.7:443");
    assert_eq!(got, Got::TimedOut, "released");
    eprintln!("release (one element out of the set): {release:?}");

    // Notice: only the probes' addresses, and nothing refused.
    hal.apply(&cfg, &profile(Mode::Notice)).unwrap();
    member(&mut hal, "bloqueados", true);
    let (got, _) = try_connect(&sub, "198.51.100.7:80");
    assert_eq!(
        got,
        Got::TimedOut,
        "a site that is not a probe host goes on"
    );
    member(&mut hal, "sn-probe", true);
    let probe = DynamicAddress {
        list: "sn-probe".parse().unwrap(),
        address: AddrMatch::Net("198.51.100.7/32".parse().unwrap()),
        timeout_secs: 600,
        added_by_rule: false,
    };
    hal.address_list_dynamic(DynamicChange::Add(&probe))
        .unwrap();
    let (got, _) = try_connect(&sub, "198.51.100.7:80");
    assert_eq!(
        got,
        Got::Connected,
        "the probe host's port 80 goes to the portal"
    );
    let (got, _) = try_connect(&sub, "198.51.100.7:443");
    assert_eq!(got, Got::TimedOut, "notice refuses nothing");
    // Seen: left alone for the interval.
    member(&mut hal, "sn-seen-atraso", true);
    let (got, _) = try_connect(&sub, "198.51.100.7:80");
    assert_eq!(got, Got::TimedOut, "seen: no more redirects");

    hal.apply(&profile(Mode::Notice), &Config::default())
        .unwrap();
}

//! G0.31c — how long `ip.firewall.connection.list`/`top` hold the session
//! lock with a big conntrack table, inside a throwaway network namespace —
//! no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_BENCH=1 unshare --user --map-root-user --net -- \
//!     cargo bench -p corerouter-daemon --bench netns_conntrack
//! ```
//!
//! UDP flows on `lo` (`COREROUTER_CONNTRACK_FLOWS`, default 250 000; the
//! namespace's table is capped by the host's `nf_conntrack_max`) fill the
//! table of a `--backend linux` session. "lock" is
//! `Session::execute_reply_as`, what the control channel runs under the
//! lock; "answer" adds `Reply::finish`, run after it. Cold: the dump is
//! older than `CACHE_SECS`, so the table is read again; warm: it is not.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("skipped: conntrack is Linux-only");
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
    use std::net::UdpSocket;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use corerouter_engine::{Caller, Session};
    use corerouter_hal_linux::{LinuxHal, ctnl};
    use serde_json::{Value, json};

    const ENV: &str = "COREROUTER_NETNS_BENCH";
    /// `CACHE_SECS` of `engine::cmd::firewall_connection` (private there).
    const CACHE_SECS: u64 = 2;
    /// Destination ports per sending socket.
    const PORTS: u32 = 5000;

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
            "{ENV}=1 but this namespace is not fresh; refusing to touch it"
        );
        true
    }

    fn sh(cmd: &str, args: &[&str]) {
        let out = Command::new(cmd).args(args).output().unwrap();
        assert!(
            out.status.success(),
            "{cmd} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// `flows` UDP flows from 127.0.0.1 to 127.0.0.1, conntrack on.
    fn fill(flows: u32) -> Duration {
        sh("ip", &["link", "set", "lo", "up"]);
        sh("nft", &["add", "table", "ip", "bench"]);
        sh(
            "nft",
            &["add chain ip bench out { type filter hook output priority 0; }"],
        );
        sh(
            "nft",
            &[
                "add", "rule", "ip", "bench", "out", "ct", "state", "new", "counter",
            ],
        );
        let t = Instant::now();
        let mut sent = 0;
        while sent < flows {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            for port in 1..=PORTS.min(flows - sent) {
                sock.send_to(b"x", ("127.0.0.1", u16::try_from(port).unwrap()))
                    .unwrap();
            }
            sent += PORTS.min(flows - sent);
        }
        t.elapsed()
    }

    fn median(mut v: Vec<Duration>) -> Duration {
        v.sort();
        v[v.len() / 2]
    }

    /// (lock, answer) of one call.
    fn once(s: &mut Session, id: &str, p: &Value) -> (Duration, Duration) {
        let t = Instant::now();
        let reply = s.execute_reply_as(&Caller::local(), id, p).unwrap();
        let lock = t.elapsed();
        let v = reply.finish().unwrap();
        assert!(!v.is_null(), "{id}");
        (lock, t.elapsed())
    }

    pub fn run() {
        let flows = std::env::var("COREROUTER_CONNTRACK_FLOWS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(250_000u32);
        let took = fill(flows);
        let count = ctnl::stats().unwrap().count;
        println!("{flows} flows sent in {took:.2?}; conntrack holds {count}");
        let mut s = Session::new(Box::new(LinuxHal::new()));
        let cases = [
            ("ip.firewall.connection.list", json!({"count": 5})),
            (
                "ip.firewall.connection.list",
                json!({"count": 50, "sort": "bytes"}),
            ),
            ("ip.firewall.connection.top", json!({})),
        ];
        println!(
            "| command | cold lock | cold answer | warm lock (median / max of 20) | warm answer |"
        );
        println!("|---|---|---|---|---|");
        for (id, p) in &cases {
            let mut cold = Vec::new();
            for _ in 0..3 {
                std::thread::sleep(Duration::from_millis(CACHE_SECS * 1000 + 100));
                cold.push(once(&mut s, id, p));
            }
            let warm: Vec<_> = (0..20).map(|_| once(&mut s, id, p)).collect();
            let wl: Vec<Duration> = warm.iter().map(|w| w.0).collect();
            let max = wl.iter().max().copied().unwrap();
            println!(
                "| `{id}` {p} | {:.2?} | {:.2?} | {:.2?} / {max:.2?} | {:.2?} |",
                median(cold.iter().map(|c| c.0).collect()),
                median(cold.iter().map(|c| c.1).collect()),
                median(wl),
                median(warm.iter().map(|w| w.1).collect()),
            );
        }
    }
}

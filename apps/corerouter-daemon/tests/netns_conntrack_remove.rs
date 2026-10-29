//! G3.9hd: `ip.firewall.connection.remove` against the kernel's conntrack,
//! on a `--backend linux` session inside a throwaway network namespace —
//! no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_conntrack_remove
//! ```
//!
//! UDP flows and a TCP connection on `lo` (an nft rule turns conntrack on):
//! remove by destination port and by id, a dry run, the caller's own TCP
//! connection kept unless asked, and the whole table only with `all`. The
//! read and the deletes run after the lock (`Reply::Later`).
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::Command;

use common::*;
use corerouter_engine::off_lock::Reply;
use corerouter_engine::{Caller, Link, Principal, Session};
use corerouter_hal_linux::{LinuxHal, ctnl};
use serde_json::{Value, json};

fn sh(cmd: &str, args: &[&str]) {
    let out = Command::new(cmd).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{cmd} {}: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr)
    );
}

/// The command as the control channel runs it: the answer comes after
/// the lock.
fn run(s: &mut Session, caller: &Caller, id: &str, p: Value) -> Value {
    let reply = s.execute_reply_as(caller, id, &p).unwrap();
    assert!(
        matches!(reply, Reply::Later(_)),
        "{id} answers under the lock"
    );
    reply.finish().unwrap()
}

/// Kernel connections to `port` on 127.0.0.2 (UDP).
fn to_port(port: u16) -> usize {
    ctnl::dump()
        .unwrap()
        .iter()
        .filter(|c| c.protocol == 17 && c.orig.dst_port == port)
        .count()
}

#[test]
fn remove_deletes_from_the_kernel_table_and_spares_the_management_connection() {
    if !in_netns() {
        return;
    }
    sh("ip", &["link", "set", "lo", "up"]);
    sh("nft", &["add", "table", "ip", "t"]);
    sh(
        "nft",
        &["add chain ip t out { type filter hook output priority 0; }"],
    );
    sh(
        "nft",
        &[
            "add", "rule", "ip", "t", "out", "ct", "state", "new", "counter",
        ],
    );
    // 3 × 20 UDP flows to ports 5001..5003 of 127.0.0.2.
    for _ in 0..20 {
        let u = UdpSocket::bind("127.0.0.1:0").unwrap();
        for port in 5001..=5003u16 {
            u.send_to(b"x", ("127.0.0.2", port)).unwrap();
        }
    }
    assert_eq!(to_port(5001), 20);
    // The "management" TCP connection.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (_server, _) = listener.accept().unwrap();
    let me = Caller::new(7, "tls test")
        .with_principal(Principal::Local)
        .with_link(Link {
            peer: client.local_addr().unwrap(),
            local: client.peer_addr().unwrap(),
        });
    let mut s = Session::new(Box::new(LinuxHal::new()));

    // A dry run counts.
    let r = run(
        &mut s,
        &me,
        "ip.firewall.connection.remove",
        json!({"protocol": "udp", "dst_port": 5001, "dry_run": true}),
    );
    assert_eq!(
        (r["matched"].as_u64(), r["removed"].as_u64()),
        (Some(20), Some(0)),
        "{r}"
    );
    assert_eq!(to_port(5001), 20);
    // By filter (conntrack -D -p udp --dport 5001).
    let r = run(
        &mut s,
        &me,
        "ip.firewall.connection.remove",
        json!({"protocol": "udp", "dst_port": 5001}),
    );
    assert_eq!(r["removed"], 20, "{r}");
    assert_eq!(to_port(5001), 0);
    assert_eq!(to_port(5002), 20);
    // The list read after it does not show them (the cache was dropped).
    let l = run(
        &mut s,
        &me,
        "ip.firewall.connection.list",
        json!({"port": 5001}),
    );
    assert_eq!(l["total"], 0, "{l}");
    // By id.
    let one = ctnl::dump()
        .unwrap()
        .into_iter()
        .find(|c| c.orig.dst_port == 5002)
        .unwrap();
    let r = run(
        &mut s,
        &me,
        "ip.firewall.connection.remove",
        json!({"id": one.id}),
    );
    assert_eq!(r["removed"], 1, "{r}");
    assert_eq!(to_port(5002), 19);
    // Everything: needs all, keeps our own TCP connection.
    assert!(
        s.execute_as(&me, "ip.firewall.connection.remove", &json!({}))
            .is_err()
    );
    let r = run(
        &mut s,
        &me,
        "ip.firewall.connection.remove",
        json!({"all": true}),
    );
    assert_eq!(r["kept_management"], 1, "{r}");
    assert!(r["removed"].as_u64().unwrap() >= 39, "{r}");
    let left = ctnl::dump().unwrap();
    assert!(
        left.iter().all(|c| c.protocol == 6),
        "only the management connection is left: {left:?}"
    );
    assert_eq!(left.len(), 1, "{left:?}");
    // Asked for, it goes too.
    let r = run(
        &mut s,
        &me,
        "ip.firewall.connection.remove",
        json!({"protocol": "tcp", "include_management": true}),
    );
    assert_eq!(r["removed"], 1, "{r}");
    assert!(
        r["warnings"][0].as_str().unwrap().contains("removed"),
        "{r}"
    );
    // Journaled, as every action.
    let last = s.journal().last().unwrap();
    assert_eq!(last.command, "ip.firewall.connection.remove");
    assert!(last.ok);
}

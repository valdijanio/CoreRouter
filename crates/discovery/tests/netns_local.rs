//! A router on this machine, heard over a link that has just come up, is
//! reached over loopback — not over its IPv6 link-local address, where the
//! control channel does not listen until G0.3. Needs a kernel:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-discovery --test netns_local
//! ```
//!
//! (`cargo xtask netns` runs it.) The listener starts before the veth
//! exists, as the GUI does when the operator creates the link afterwards;
//! the router's link-local address is still tentative when it is first
//! seen. Helpers outside `#[test]` fns may unwrap/panic too.
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::SocketAddr;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_discovery::{Agent, AgentConfig, Listener, NodeId, Transport};
use corerouter_engine::{Session, shared};
use serde_json::json;

const ENV: &str = "COREROUTER_NETNS_TESTS";
const PORT: u16 = 7979;

fn ip(args: &[&str]) {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(
        out.status.success(),
        "ip {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn a_router_on_this_machine_is_reached_over_loopback_on_a_new_link() {
    if std::env::var_os(ENV).is_none() {
        eprintln!("skipped: run with {ENV}=1 in a network namespace (cargo xtask netns)");
        return;
    }
    ip(&["link", "set", "lo", "up"]);
    let mut listener = Listener::spawn(PORT).unwrap();

    let mut s = Session::virtual_lab();
    s.execute(
        "ip.neighbor.discovery.set",
        &json!({ "interfaces": ["ether1"], "interval_secs": 1 }),
    )
    .unwrap();
    let _agent = Agent::spawn(
        shared(s),
        AgentConfig {
            port: PORT,
            node_id: NodeId([7; 16]),
            control_port: Some(7981),
            ws_port: None,
            tls_port: None,
            wss_port: None,
            board: "test".into(),
            transport: Transport::Interfaces,
        },
    )
    .unwrap();
    // Both ends in this namespace: the announcement leaves ether1 and comes
    // back in on peer1, with the link-local source of ether1.
    ip(&[
        "link", "add", "ether1", "type", "veth", "peer", "name", "peer1",
    ]);
    ip(&["link", "set", "ether1", "up"]);
    ip(&["link", "set", "peer1", "up"]);

    let start = Instant::now();
    let mut seen_v6 = false;
    let mut samples = 0;
    while start.elapsed() < Duration::from_secs(20) && (samples < 40 || !seen_v6) {
        if let Some(h) = listener.poll().first().map(|h| (*h).clone()) {
            seen_v6 |= matches!(h.from, SocketAddr::V6(a) if a.ip().is_unicast_link_local());
            assert!(h.local, "heard from {} but not as this machine", h.from);
            assert_eq!(h.connect_to().as_deref(), Some("127.0.0.1:7981"));
            samples += 1;
        }
        thread::sleep(Duration::from_millis(100));
    }
    assert!(seen_v6, "no announcement over IPv6 link-local arrived");
}

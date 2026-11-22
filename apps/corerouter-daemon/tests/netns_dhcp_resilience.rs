//! G4.7c: DHCP client resilience on a `--backend linux` daemon, inside
//! throwaway network namespaces (no root, nothing reaches the host):
//! check-gateway by ARP withdraws the default route from the kernel while
//! the gateway is silent, and a restarted daemon asks for its remembered
//! lease with INIT-REBOOT (a REQUEST, no DISCOVER).
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_dhcp_resilience
//! ```
//!
//! Same topology and test server as `netns_dhcp.rs` (G4.7a).
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::*;
use corerouter_hal::dhcp::{Dest, DhcpResponder};
use corerouter_proto_dhcp::lab::LabServer;
use corerouter_proto_dhcp::v4;
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
    run("ip.dhcp-client.list", json!({})).unwrap()[0].clone()
}

/// The test server: what it received (message types).
struct Server {
    seen: Arc<Mutex<Vec<u8>>>,
    stop: Arc<AtomicBool>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Serve DHCP on `srv0` inside the namespace of `pid`.
fn serve_in(pid: u32) -> Server {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let (s2, st2) = (seen.clone(), stop.clone());
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let ns = std::fs::File::open(format!("/proc/{pid}/ns/net")).unwrap();
        nix::sched::setns(ns, nix::sched::CloneFlags::CLONE_NEWNET).unwrap();
        let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP)).unwrap();
        sock.set_reuse_address(true).unwrap();
        sock.set_broadcast(true).unwrap();
        sock.bind_device(Some(b"srv0")).unwrap();
        sock.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, 67)).into())
            .unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let sock: std::net::UdpSocket = sock.into();
        ready_tx.send(()).unwrap();
        let lab = LabServer::default();
        let port = "ether1".parse().unwrap();
        let mut buf = [0u8; 2048];
        while !st2.load(Ordering::Relaxed) {
            let Ok((n, _from)) = sock.recv_from(&mut buf) else {
                continue;
            };
            let bytes = &buf[..n];
            let kind = v4::raw_options(bytes)
                .into_iter()
                .find(|(c, _)| *c == 53)
                .and_then(|(_, d)| d.first().copied())
                .unwrap_or(0);
            s2.lock().unwrap().push(kind);
            if n < 34 {
                continue;
            }
            let mac: [u8; 6] = bytes[28..34].try_into().unwrap();
            let ciaddr = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
            let to = if ciaddr.is_unspecified() {
                Ipv4Addr::BROADCAST
            } else {
                ciaddr
            };
            for d in lab.answer(&port, mac, bytes, Dest::Broadcast) {
                let _ = sock.send_to(&d.payload, SocketAddr::from((to, 68)));
            }
        }
    });
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    Server { seen, stop }
}

#[test]
fn query_helper() {
    common::query_helper();
}

fn spawn_daemon(dir: &std::path::Path) -> Kill {
    let log = std::fs::File::create(std::env::temp_dir().join("g47c-netns.log")).unwrap();
    let mut c = Command::new(DAEMON);
    c.args([
        "--backend",
        "linux",
        "--no-discovery",
        "--manage",
        "wan0",
        "--control",
        PORT,
        "--config-dir",
    ])
    .arg(dir)
    .arg("--token-file")
    .arg(common::token_file(None, dir))
    .env("RUST_LOG", "info")
    .stdout(Stdio::null())
    .stderr(log);
    let daemon = Kill(c.spawn().unwrap());
    wait_for("the daemon", || run("interface.list", json!({})).is_ok());
    daemon
}

#[test]
fn linux_check_gateway_and_init_reboot() {
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
    ip(bpid, &["link", "set", "lo", "up"]);
    ip(bpid, &["addr", "add", "100.64.1.1/24", "dev", "srv0"]);
    ip(bpid, &["link", "set", "srv0", "up"]);
    ip(None, &["link", "set", "wan0", "up"]);
    let server = serve_in(b.0.id());

    let dir = std::env::temp_dir().join(format!("g47c-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let daemon = spawn_daemon(&dir);
    run(
        "ip.dhcp-client.add",
        json!({"interface": "wan0", "check_gateway": "arp"}),
    )
    .unwrap();
    wait_for("a lease", || client_row()["status"] == "bound");
    wait_for("the gateway check", || {
        client_row()["gateway_status"] == "up"
    });
    let address = client_row()["address"].as_str().unwrap().to_owned();
    assert!(ip_out(&["route", "show"]).contains("default via 100.64.1.1 dev wan0"));

    // The gateway goes quiet (its address leaves srv0; the DHCP server's
    // socket stays): after 2 unanswered ARP checks the kernel loses the
    // default route, and gets it back at the first answer.
    ip(bpid, &["addr", "del", "100.64.1.1/24", "dev", "srv0"]);
    wait_for("the gateway down", || {
        client_row()["gateway_status"] == "down"
    });
    let routes = ip_out(&["route", "show"]);
    assert!(!routes.contains("default via 100.64.1.1"), "{routes}");
    ip(bpid, &["addr", "add", "100.64.1.1/24", "dev", "srv0"]);
    wait_for("the gateway up", || client_row()["gateway_status"] == "up");
    let routes = ip_out(&["route", "show"]);
    assert!(
        routes.contains("default via 100.64.1.1 dev wan0"),
        "{routes}"
    );

    // The lease is remembered on disk, outside the config.
    let saved = std::fs::read_to_string(dir.join("state-dhcp-leases.json")).unwrap();
    assert!(saved.contains(&address), "{saved}");

    // Restart: the first message is a REQUEST (INIT-REBOOT), not a DISCOVER.
    drop(daemon);
    let before = server.seen.lock().unwrap().len();
    let _daemon = spawn_daemon(&dir);
    wait_for("the lease again", || {
        run("ip.dhcp-client.list", json!({})).is_ok_and(|r| r[0]["status"] == "bound")
    });
    assert_eq!(client_row()["address"], address);
    let seen = server.seen.lock().unwrap()[before..].to_vec();
    assert_eq!(
        seen.first(),
        Some(&3),
        "INIT-REBOOT starts with a REQUEST: {seen:?}"
    );
    assert!(!seen.contains(&1), "no DISCOVER: {seen:?}");
    let history = run("ip.dhcp-client.history", json!({})).unwrap();
    assert!(
        history["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["event"] == "rebooting"),
        "{history}"
    );

    drop(_daemon);
    drop(server);
    ip(None, &["link", "del", "wan0"]);
    let _ = std::fs::remove_dir_all(&dir);
}

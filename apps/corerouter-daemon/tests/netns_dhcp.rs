//! G4.7a: a `--backend linux` daemon's DHCP client gets an address and a
//! default route from a DHCP server across a veth, renews by unicast and
//! gives everything back on release — inside throwaway network namespaces,
//! no root, nothing reaches the host:
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-daemon --test netns_dhcp
//! ```
//!
//! ```text
//!   this ns: daemon            namespace B: test DHCP server (a thread
//!   wan0 ───────── veth ─────── srv0 100.64.1.1/24   setns'd into B)
//! ```
//!
//! The server is written here, in Rust: a UDP socket on port 67 bound to
//! `srv0`, answering with the lab server's logic (`proto_dhcp::lab`), so the
//! lease is `100.64.1.H/24`, router `100.64.1.1`, option 121 with
//! `0.0.0.0/0` and `10.200.0.0/16` (see `docs/dhcp-client.md`).
//! Helpers outside `#[test]` fns may unwrap/panic too.
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

const PORT: &str = "7997";

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

/// The test server: what it received (message types) and whether it answers.
struct Server {
    seen: Arc<Mutex<Vec<u8>>>,
    silent: Arc<AtomicBool>,
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
    let silent = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let (s2, q2, st2) = (seen.clone(), silent.clone(), stop.clone());
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
            if q2.load(Ordering::Relaxed) || n < 34 {
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
    Server { seen, silent, stop }
}

#[test]
fn query_helper() {
    common::query_helper();
}

#[test]
fn linux_dhcp_client_gets_renews_and_releases_a_lease() {
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

    let dir = std::env::temp_dir().join(format!("g47a-netns-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let log = std::fs::File::create(std::env::temp_dir().join("g47a-netns.log")).unwrap();
    let mut c = Command::new(DAEMON);
    c.args([
        "--backend",
        "linux",
        "--no-discovery",
        // A veth whose peer is in another namespace looks like a container's.
        "--manage",
        "wan0",
        "--control",
        PORT,
        "--config-dir",
    ])
    .arg(&dir)
    .arg("--token-file")
    .arg(common::token_file(None, &dir))
    .env("RUST_LOG", "info")
    .stdout(Stdio::null())
    .stderr(log);
    let daemon = Kill(c.spawn().unwrap());
    wait_for("the daemon", || run("interface.list", json!({})).is_ok());

    run("ip.dhcp-client.add", json!({"interface": "wan0"})).unwrap();
    wait_for("a lease", || client_row()["status"] == "bound");
    let row = client_row();
    let address = row["address"].as_str().unwrap().to_owned();
    assert!(
        address.starts_with("100.64.1.") && address.ends_with("/24"),
        "{row}"
    );
    assert_eq!(row["gateway"], "100.64.1.1");
    assert_eq!(row["dhcp_server"], "100.64.1.1");

    // In this namespace's kernel: the address and the routes of option 121.
    assert!(ip_out(&["-br", "addr", "show", "dev", "wan0"]).contains(&address));
    let routes = ip_out(&["route", "show"]);
    assert!(
        routes.contains("default via 100.64.1.1 dev wan0"),
        "{routes}"
    );
    assert!(
        routes.contains("10.200.0.0/16 via 100.64.1.254 dev wan0"),
        "{routes}"
    );
    // The router reaches the server through its new address.
    let ping = Command::new("ping")
        .args(["-c", "1", "-W", "2", "100.64.1.1"])
        .output()
        .unwrap();
    assert!(ping.status.success(), "ping the server");

    // Renew: a unicast REQUEST, answered, still bound.
    let before = server.seen.lock().unwrap().len();
    let r = run("ip.dhcp-client.renew", json!({"id": row["id"]})).unwrap();
    wait_for("the renewal", || {
        server.seen.lock().unwrap().len() > before && client_row()["status"] == "bound"
    });
    let _ = r;
    assert!(
        run("ip.dhcp-client.history", json!({})).unwrap()["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["event"] == "renewed"),
        "renewed is in the history"
    );

    // Release with the server quiet: RELEASE reaches it, the kernel loses
    // the address and the routes, the client goes back to searching.
    server.silent.store(true, Ordering::Relaxed);
    run("ip.dhcp-client.release", json!({"id": row["id"]})).unwrap();
    wait_for("the RELEASE", || server.seen.lock().unwrap().contains(&7));
    assert!(!ip_out(&["-br", "addr", "show", "dev", "wan0"]).contains(&address));
    let routes = ip_out(&["route", "show"]);
    assert!(!routes.contains("100.64.1.1"), "{routes}");
    assert_eq!(client_row()["status"], "searching");

    drop(daemon);
    drop(server);
    ip(None, &["link", "del", "wan0"]);
    let _ = std::fs::remove_dir_all(&dir);
}

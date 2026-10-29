//! The virtual lab never tries the host's interfaces, so its config-only
//! addresses (ether1 10.0.0.1/24, which the host does not have) produce no
//! warning; the interfaces transport warns once per problem, not every
//! interval. Its own test binary: it installs the process-wide logger.
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::UdpSocket;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use corerouter_discovery::{Agent, AgentConfig, NodeId, Transport};
use corerouter_engine::{Session, shared};
use serde_json::json;

static WARNINGS: Mutex<Vec<String>> = Mutex::new(Vec::new());

struct Capture;

impl log::Log for Capture {
    fn enabled(&self, m: &log::Metadata<'_>) -> bool {
        m.level() <= log::Level::Warn
    }

    fn log(&self, r: &log::Record<'_>) {
        if self.enabled(r.metadata()) {
            WARNINGS.lock().unwrap().push(r.args().to_string());
        }
    }

    fn flush(&self) {}
}

static LOGGER: Capture = Capture;

fn warnings_about(needle: &str) -> usize {
    WARNINGS
        .lock()
        .unwrap()
        .iter()
        .filter(|w| w.contains(needle))
        .count()
}

/// Several announcement intervals (1 s) of an agent whose ether1 has an
/// address only the config knows about.
fn run(transport: Transport, id: u8) {
    let port = UdpSocket::bind("0.0.0.0:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let mut s = Session::virtual_lab();
    s.execute(
        "ip.address.add",
        &json!({ "address": "10.255.0.1/24", "interface": "ether1" }),
    )
    .unwrap();
    s.execute(
        "ip.neighbor.discovery.set",
        &json!({ "interfaces": ["ether1"], "interval_secs": 1 }),
    )
    .unwrap();
    let agent = Agent::spawn(
        shared(s),
        AgentConfig {
            port,
            node_id: NodeId([id; 16]),
            control_port: Some(7981),
            ws_port: None,
            tls_port: None,
            wss_port: None,
            board: "test".into(),
            transport,
        },
    )
    .unwrap();
    thread::sleep(Duration::from_millis(4500));
    drop(agent);
}

/// Slow layer (G0.30, `slow_`): the agent announces on real sockets every
/// second (the shortest interval) and the test listens for several
/// intervals, twice: ~9 s of waiting.
#[test]
fn slow_config_only_addresses_warn_never_in_the_lab_and_once_on_linux() {
    log::set_logger(&LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Warn);

    run(Transport::Loopback, 1);
    let lab: Vec<String> = WARNINGS.lock().unwrap().clone();
    assert!(lab.is_empty(), "the lab warned: {lab:?}");

    run(Transport::Interfaces, 2);
    assert_eq!(
        warnings_about("cannot broadcast from 10.255.0.1 on ether1"),
        1,
        "{:?}",
        WARNINGS.lock().unwrap()
    );
}

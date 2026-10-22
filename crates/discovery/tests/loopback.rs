//! G5.4: virtual labs on one host see each other over loopback, with no
//! network namespace and no root. Each test uses its own free UDP port, so
//! it neither hears nor disturbs CRDP processes already on this machine.
//!
//! Helpers outside `#[test]` fns may unwrap/panic too.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::net::UdpSocket;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_discovery::{
    Agent, AgentConfig, LAB_INTERFACE, Listener, NodeId, Transport, enable_lab_default,
};
use corerouter_engine::{Session, Shared, lock, shared};
use serde_json::{Value, json};

const WAIT: Duration = Duration::from_secs(10);

fn free_udp_port() -> u16 {
    UdpSocket::bind("0.0.0.0:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A virtual lab like `corerouter-daemon --control <control>`: factory
/// default discovery, announcing every second so the test is quick.
fn lab(identity: &str) -> Shared {
    let mut s = Session::virtual_lab();
    enable_lab_default(&mut s).unwrap();
    s.execute("system.identity.set", &json!({ "name": identity }))
        .unwrap();
    s.execute("ip.neighbor.discovery.set", &json!({ "interval_secs": 1 }))
        .unwrap();
    shared(s)
}

fn agent(session: &Shared, port: u16, id: u8, control: u16, transport: Transport) -> Agent {
    Agent::spawn(
        session.clone(),
        AgentConfig {
            port,
            node_id: NodeId([id; 16]),
            control_port: Some(control),
            ws_port: None,
            board: "test".into(),
            transport,
        },
    )
    .unwrap()
}

fn neighbors(s: &Shared) -> Vec<Value> {
    let v = lock(s).execute("ip.neighbor.list", &json!({})).unwrap();
    match v {
        Value::Array(a) => a,
        other => other["neighbors"].as_array().cloned().unwrap_or_default(),
    }
}

fn wait_for(mut done: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < WAIT {
        if done() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }
    false
}

fn sees(s: &Shared, identity: &str) -> Option<Value> {
    neighbors(s).into_iter().find(|n| n["identity"] == identity)
}

#[test]
fn two_labs_and_the_gui_listener_see_each_other_over_loopback() {
    let port = free_udp_port();
    let mut listener = Listener::spawn(port).unwrap();
    let (a, b) = (lab("lab-a"), lab("lab-b"));
    let _aa = agent(&a, port, 1, 7979, Transport::Loopback);
    let _ab = agent(&b, port, 2, 7981, Transport::Loopback);

    assert!(wait_for(
        || sees(&a, "lab-b").is_some() && sees(&b, "lab-a").is_some()
    ));
    let n = sees(&a, "lab-b").unwrap();
    assert_eq!(n["interface"], LAB_INTERFACE);
    assert_eq!(n["remote_interface"], LAB_INTERFACE);
    assert_eq!(n["protocol"], "crdp", "{n}");
    assert_eq!(n["mgmt"]["control"], 7981);
    // A lab does not list itself.
    assert!(sees(&a, "lab-a").is_none());

    // The native GUI's connect screen: both, reachable over loopback.
    let mut targets = Vec::new();
    assert!(wait_for(|| {
        targets = listener
            .poll()
            .iter()
            .filter_map(|h| h.connect_to())
            .collect();
        targets.len() == 2
    }));
    targets.sort();
    assert_eq!(targets, ["127.0.0.1:7979", "127.0.0.1:7981"]);
}

/// G5.5: stopping an agent says goodbye: the other lab and the GUI
/// listener forget it at once instead of after the hold time (4 s here).
#[test]
fn shutdown_says_goodbye_to_labs_and_the_gui_listener() {
    let port = free_udp_port();
    let mut listener = Listener::spawn(port).unwrap();
    let (a, b) = (lab("bye-a"), lab("bye-b"));
    let _aa = agent(&a, port, 3, 7979, Transport::Loopback);
    let ab = agent(&b, port, 4, 7981, Transport::Loopback);
    assert!(wait_for(|| sees(&a, "bye-b").is_some()));
    assert!(wait_for(|| listener.poll().len() == 2));

    let start = Instant::now();
    assert_eq!(ab.shutdown(Duration::from_secs(1)), Some(1));
    assert!(
        start.elapsed() < Duration::from_secs(1),
        "{:?}",
        start.elapsed()
    );
    let gone = |l: &mut Listener| {
        let ids: Vec<NodeId> = l.poll().iter().map(|h| h.announcement.node_id).collect();
        ids == [NodeId([3; 16])]
    };
    let deadline = Instant::now() + Duration::from_millis(1500);
    while Instant::now() < deadline && !(sees(&a, "bye-b").is_none() && gone(&mut listener)) {
        thread::sleep(Duration::from_millis(50));
    }
    assert!(sees(&a, "bye-b").is_none(), "lab a still lists bye-b");
    assert!(gone(&mut listener), "the GUI listener still lists bye-b");
}

#[test]
fn a_lab_hears_only_on_its_port_of_the_same_name() {
    let port = free_udp_port();
    let (a, b) = (lab("lab-a"), lab("lab-b"));
    // b moves its discovery to ether2: a's ether1 announcements have no
    // matching active port on b, and b's ether2 none on a.
    lock(&b)
        .execute(
            "ip.neighbor.discovery.set",
            &json!({ "interfaces": ["ether2"] }),
        )
        .unwrap();
    let _aa = agent(&a, port, 1, 7979, Transport::Loopback);
    let _ab = agent(&b, port, 2, 7981, Transport::Loopback);
    thread::sleep(Duration::from_secs(3));
    assert!(neighbors(&a).is_empty());
    assert!(neighbors(&b).is_empty());

    // Same port name on both: they meet.
    lock(&b)
        .execute(
            "ip.neighbor.discovery.set",
            &json!({ "interfaces": ["ether1", "ether2"] }),
        )
        .unwrap();
    assert!(wait_for(
        || sees(&a, "lab-b").is_some() && sees(&b, "lab-a").is_some()
    ));
    assert_eq!(sees(&b, "lab-a").unwrap()["interface"], "ether1");
}

/// `--backend linux` is unchanged: it never announces on loopback, and a
/// lab's loopback announcement is not a neighbor of any of its links.
#[test]
fn interfaces_transport_ignores_the_loopback_wire() {
    let port = free_udp_port();
    let mut listener = Listener::spawn(port).unwrap();
    let real = lab("real");
    // An address the host does not have: nothing to send from, as before.
    lock(&real)
        .execute(
            "ip.address.add",
            &json!({ "address": "10.255.0.1/24", "interface": LAB_INTERFACE }),
        )
        .unwrap();
    let virt = lab("virt");
    let _real = agent(&real, port, 1, 7979, Transport::Interfaces);
    let _virt = agent(&virt, port, 2, 7981, Transport::Loopback);

    // The lab is heard on loopback (the transport works) ...
    assert!(wait_for(|| listener.poll().len() == 1));
    thread::sleep(Duration::from_secs(3));
    let heard: Vec<String> = listener
        .poll()
        .iter()
        .map(|h| h.announcement.identity.clone())
        .collect();
    // ... the linux-style agent never was, and did not record the lab.
    assert_eq!(heard, ["virt"]);
    assert!(neighbors(&real).is_empty());
    assert!(neighbors(&virt).is_empty());
}

//! G1.19 — the interface dialog's queries: `interface.ethernet.monitor`,
//! `interface.hardware`, `interface.stats`. They answer for every interface
//! that exists; what the platform cannot say comes back as
//! `available: false` with the reason, never as an error.
// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::Session;
use corerouter_hal::{Hal, HalError, LinkInfo, LinkState, VirtualHal};
use corerouter_model::Config;
use serde_json::{Value, json};

fn lab() -> Session {
    Session::virtual_lab()
}

fn run(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn counter(stats: &Value, group: &str, name: &str) -> u64 {
    stats["groups"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["name"] == group)
        .and_then(|g| {
            g["counters"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"] == name)
        })
        .unwrap_or_else(|| panic!("no {group}/{name} in {stats}"))["value"]
        .as_u64()
        .unwrap()
}

#[test]
fn monitor_reads_like_routeros() {
    let mut s = lab();
    let m = run(
        &mut s,
        "interface.ethernet.monitor",
        json!({"name": "ether1"}),
    );
    assert_eq!(m["available"], true, "{m}");
    assert_eq!(m["reason"], Value::Null);
    assert_eq!(m["status"], "link-ok");
    assert_eq!(m["rate"], "1Gbps");
    assert_eq!(m["speed_mbps"], 1000);
    assert_eq!(m["full_duplex"], true);
    assert_eq!(m["auto_negotiation"], "done");
    assert!(
        m["supported_modes"]
            .as_array()
            .unwrap()
            .contains(&json!("1000baseT/Full"))
    );
    assert_eq!(m["link_partner_advertising"], m["advertising"]);
    assert_eq!(m["link_downs"], 0);
    // The lab's last port is its 10G one.
    let fast = run(
        &mut s,
        "interface.ethernet.monitor",
        json!({"name": "ether8"}),
    );
    assert_eq!(fast["rate"], "10Gbps");
}

#[test]
fn hardware_and_stats_of_a_lab_port() {
    let mut s = lab();
    let hw = run(&mut s, "interface.hardware", json!({"name": "ether2"}));
    assert_eq!(hw["available"], true, "{hw}");
    assert_eq!(hw["vendor"], "CoreRouter");
    assert_eq!(hw["model"], "Virtual NIC");
    assert_eq!(hw["driver"], "corerouter-virt");
    assert_eq!(hw["perm_mac"], "02:00:00:00:00:02");
    assert_eq!(hw["vendor_id"], Value::Null);
    assert_eq!(hw["max_mtu"], 9216);
    assert!(
        hw["offloads"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o["name"] == "GRO" && o["active"] == true)
    );
    let st = run(&mut s, "interface.stats", json!({"name": "ether2"}));
    assert_eq!(st["available"], true);
    let groups: Vec<&str> = st["groups"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["name"].as_str().unwrap())
        .collect();
    assert_eq!(groups, ["interface", "eth-mac", "rmon", "pause"]);
    assert!(counter(&st, "interface", "rx_bytes") > 0);
    assert_eq!(counter(&st, "pause", "rx_pause_frames"), 0);
}

#[test]
fn missing_interface_is_an_error() {
    let mut s = lab();
    for id in [
        "interface.ethernet.monitor",
        "interface.hardware",
        "interface.stats",
    ] {
        let e = s.execute(id, &json!({"name": "nosuch9"})).unwrap_err();
        assert!(
            e.to_string().contains("no interface 'nosuch9'"),
            "{id}: {e}"
        );
        let e = s.execute(id, &json!({})).unwrap_err();
        assert!(e.to_string().contains("name"), "{id}: {e}");
        let e = s.execute(id, &json!({"name": "a/b"})).unwrap_err();
        assert!(e.to_string().contains("name"), "{id}: {e}");
    }
}

#[test]
fn software_interface_is_not_ethernet_but_still_answers() {
    let mut s = lab();
    run(&mut s, "interface.bridge.add", json!({"name": "br1"}));
    let m = run(&mut s, "interface.ethernet.monitor", json!({"name": "br1"}));
    assert_eq!(m["available"], false);
    assert!(
        m["reason"]
            .as_str()
            .unwrap()
            .contains("not an Ethernet port"),
        "{m}"
    );
    assert_eq!(m["status"], "link-ok", "from the link state");
    assert_eq!(m["rate"], Value::Null);
    let hw = run(&mut s, "interface.hardware", json!({"name": "br1"}));
    assert_eq!(hw["available"], true);
    assert_eq!(hw["driver"], "bridge");
}

/// A platform that implements none of the G1.19 queries (the trait's
/// defaults): everything is "not supported", nothing fails.
struct Bare(VirtualHal);

impl Hal for Bare {
    fn describe(&self) -> String {
        "bare".into()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.0.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        self.0.apply(from, to)
    }
    fn poll(&mut self) -> Vec<LinkState> {
        self.0.poll()
    }
    fn now_unix(&self) -> Option<u64> {
        None
    }
}

#[test]
fn unsupported_platform_answers_with_the_reason() {
    let mut s = Session::new(Box::new(Bare(VirtualHal::new(2))));
    let m = run(
        &mut s,
        "interface.ethernet.monitor",
        json!({"name": "ether1"}),
    );
    assert_eq!(m["available"], false);
    assert!(
        m["reason"]
            .as_str()
            .unwrap()
            .contains("bare has no Ethernet state")
    );
    assert_eq!(m["status"], "link-ok");
    let hw = run(&mut s, "interface.hardware", json!({"name": "ether1"}));
    assert_eq!(hw["available"], false);
    assert_eq!(hw["vendor"], Value::Null);
    let st = run(&mut s, "interface.stats", json!({"name": "ether1"}));
    assert_eq!(st["available"], false);
    // The counters `interface.list` has are still there.
    assert!(counter(&st, "interface", "rx_bytes") > 0);
}

#[test]
fn link_times_follow_the_clock() {
    let mut s = lab();
    let monitor = |s: &mut Session| run(s, "interface.ethernet.monitor", json!({"name": "ether2"}));
    let m = monitor(&mut s);
    assert_eq!(m["watching_since"], Value::Null, "no clock yet");
    assert_eq!(m["link_downs"], 1, "the lab's simulated history");

    s.tick(1_000);
    let m = monitor(&mut s);
    assert_eq!(m["watching_since"], 1_000);
    assert_eq!(m["now"], 1_000);
    assert_eq!(
        m["last_link_up_time"],
        Value::Null,
        "up since before watching"
    );

    run(
        &mut s,
        "interface.set",
        json!({"name": "ether2", "disabled": true}),
    );
    s.tick(1_005);
    let m = monitor(&mut s);
    assert_eq!(m["status"], "no-link");
    assert_eq!(m["auto_negotiation"], "incomplete");
    assert_eq!(m["last_link_down_time"], 1_005);

    run(
        &mut s,
        "interface.set",
        json!({"name": "ether2", "disabled": false}),
    );
    s.tick(1_010);
    let m = monitor(&mut s);
    assert_eq!(m["status"], "link-ok");
    assert_eq!(m["last_link_up_time"], 1_010);
    assert_eq!(m["last_link_down_time"], 1_005);
    assert_eq!(m["link_downs"], 2);
}

#[test]
fn queries_leave_no_journal_and_no_revision() {
    let mut s = lab();
    let before = (s.journal().len(), s.store().current_revision());
    for id in [
        "interface.ethernet.monitor",
        "interface.hardware",
        "interface.stats",
    ] {
        run(&mut s, id, json!({"name": "ether1"}));
    }
    assert_eq!((s.journal().len(), s.store().current_revision()), before);
}

#[test]
fn terminal_takes_the_name_bare() {
    let spec = corerouter_engine::cmd::find("interface.ethernet.monitor").unwrap();
    assert_eq!(spec.positional, Some("name"));
    assert!(!spec.journal);
}

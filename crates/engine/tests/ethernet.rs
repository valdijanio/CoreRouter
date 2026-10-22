//! G1.20 — `interface.ethernet.set` (link settings checked against what the
//! port can do, in the config with journal and rollback, Safe Mode on the
//! management port), the SFP module in `interface.ethernet.monitor`, and
//! `interface.ethernet.cable-test` as a task. On the virtual lab: ether1..7
//! are 1G copper, ether8 an SFP+ cage with a 10GBASE-SR module.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::{Caller, Clock, EngineError, Job, Principal, Runner, Session};
use corerouter_hal::sff::{self, SfpModule};
use corerouter_hal::{EthernetMonitor, Hal, HalError, LinkInfo, LinkState, VirtualHal};
use corerouter_model::{Config, IfName};
use serde_json::{Value, json};

struct Threads;
struct Wall(Instant);

impl Clock for Wall {
    fn elapsed(&self) -> Duration {
        self.0.elapsed()
    }
    fn sleep(&self, d: Duration) {
        thread::sleep(d);
    }
}

impl Runner for Threads {
    fn spawn(&self, _name: &str, job: Job) -> Result<(), String> {
        thread::spawn(move || job(&Wall(Instant::now())));
        Ok(())
    }
}

fn lab() -> Session {
    Session::virtual_lab()
}

fn run(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn fails(s: &mut Session, id: &str, p: Value) -> String {
    match s.execute(id, &p) {
        Ok(v) => panic!("{id} {p} should fail, got {v}"),
        Err(e) => e.to_string(),
    }
}

fn monitor(s: &mut Session, name: &str) -> Value {
    run(s, "interface.ethernet.monitor", json!({ "name": name }))
}

fn set(s: &mut Session, p: Value) -> Value {
    run(s, "interface.ethernet.set", p)
}

#[test]
fn forcing_the_rate_shows_in_the_monitor_and_rolls_back() {
    let mut s = lab();
    let before = s.store().current_revision();
    let r = set(
        &mut s,
        json!({"name": "ether2", "auto_negotiation": false, "speed": "100Mbps", "duplex": "full"}),
    );
    assert_eq!(r["ethernet"]["auto_negotiation"], false);
    assert_eq!(r["ethernet"]["speed_mbps"], 100);
    assert!(
        r["warnings"][0].as_str().unwrap().contains("other end"),
        "{r}"
    );
    let m = monitor(&mut s, "ether2");
    assert_eq!(m["rate"], "100Mbps");
    assert_eq!(m["auto_negotiation"], "disabled");
    assert_eq!(m["configured"]["speed_mbps"], 100);
    // In the config, the journal and the history.
    assert_eq!(s.store().current_revision(), before + 1);
    let ether2 = s
        .store()
        .running()
        .interfaces
        .values()
        .find(|i| i.name.as_str() == "ether2");
    assert_eq!(ether2.unwrap().ethernet.speed_mbps, Some(100));
    let journal = s.inspect(Some("journal")).unwrap();
    assert!(
        journal.to_string().contains("interface.ethernet.set"),
        "{journal}"
    );

    run(&mut s, "config.rollback", json!({ "revision": before }));
    let m = monitor(&mut s, "ether2");
    assert_eq!(m["rate"], "1Gbps");
    assert_eq!(m["auto_negotiation"], "done");
    assert_eq!(m["configured"], json!({}), "nothing set: the port's own");
}

#[test]
fn advertise_accepts_routeros_and_kernel_names() {
    let mut s = lab();
    set(
        &mut s,
        json!({"name": "ether3", "advertise": "100M-baseT-full,10baseT/Full"}),
    );
    let m = monitor(&mut s, "ether3");
    assert_eq!(m["advertising"], json!(["100baseT/Full", "10baseT/Full"]));
    assert_eq!(m["rate"], "100Mbps", "the best advertised mode wins");
    set(&mut s, json!({"name": "ether3", "advertise": ["all"]}));
    assert_eq!(monitor(&mut s, "ether3")["rate"], "1Gbps");
    set(&mut s, json!({"name": "ether3", "reset": true}));
    assert_eq!(monitor(&mut s, "ether3")["configured"], json!({}));
}

#[test]
fn what_the_port_cannot_do_is_refused_before_applying() {
    let mut s = lab();
    let rev = s.store().current_revision();
    let e = fails(
        &mut s,
        "interface.ethernet.set",
        json!({"name": "ether1", "auto_negotiation": false, "speed": "10Gbps"}),
    );
    assert!(
        e.contains("cannot be forced to 10Gbps") && e.contains("1000baseT/Full"),
        "{e}"
    );
    let e = fails(
        &mut s,
        "interface.ethernet.set",
        json!({"name": "ether1", "auto_negotiation": false, "speed": "1Gbps"}),
    );
    assert!(
        e.contains("needs auto-negotiation") && e.contains("advertise=1000baseT/Full"),
        "{e}"
    );
    let e = fails(
        &mut s,
        "interface.ethernet.set",
        json!({"name": "ether1", "speed": "100Mbps"}),
    );
    assert!(e.contains("auto_negotiation=false"), "{e}");
    let e = fails(
        &mut s,
        "interface.ethernet.set",
        json!({"name": "ether1", "advertise": "10G-baseSR-LR"}),
    );
    assert!(e.contains("does not support"), "{e}");
    let e = fails(
        &mut s,
        "interface.ethernet.set",
        json!({"name": "ether1", "advertise": "fast"}),
    );
    assert!(e.contains("not a link mode"), "{e}");
    let e = fails(
        &mut s,
        "interface.ethernet.set",
        json!({"name": "ether1", "duplex": "both"}),
    );
    assert!(e.contains("duplex"), "{e}");
    let e = fails(
        &mut s,
        "interface.ethernet.set",
        json!({"name": "ether1", "rx_flow_control": "sometimes"}),
    );
    assert!(e.contains("on, off or auto"), "{e}");
    let e = fails(
        &mut s,
        "interface.ethernet.set",
        json!({"name": "ether1", "offloads": "lro:on"}),
    );
    assert!(e.contains("fixed off"), "{e}");
    let e = fails(
        &mut s,
        "interface.ethernet.set",
        json!({"name": "ether1", "offloads": "warp:on"}),
    );
    assert!(e.contains("not an offload"), "{e}");
    let e = fails(
        &mut s,
        "interface.ethernet.set",
        json!({"name": "nope", "speed": "1Gbps"}),
    );
    assert!(e.contains("no interface 'nope'"), "{e}");
    run(&mut s, "interface.bridge.add", json!({"name": "br9"}));
    let rev_bridge = s.store().current_revision();
    let e = fails(
        &mut s,
        "interface.ethernet.set",
        json!({"name": "br9", "auto_negotiation": true}),
    );
    assert!(e.contains("physical ports"), "{e}");
    assert_eq!(s.store().current_revision(), rev_bridge);
    assert_eq!(rev_bridge, rev + 1, "only the bridge made a revision");
    // Forcing a rate the SFP+ port supports is fine (1000BASE-X is not copper).
    set(
        &mut s,
        json!({"name": "ether8", "auto_negotiation": false, "speed": "1G-baseX"}),
    );
    assert_eq!(monitor(&mut s, "ether8")["rate"], "1Gbps");
}

#[test]
fn flow_control_and_offloads() {
    let mut s = lab();
    set(
        &mut s,
        json!({"name": "ether4", "rx_flow_control": "on", "tx_flow_control": "auto"}),
    );
    let m = monitor(&mut s, "ether4");
    assert_eq!(m["rx_flow_control"], true);
    assert_eq!(m["tx_flow_control"], true);
    assert_eq!(m["flow_control_autoneg"], true);
    assert_eq!(m["configured"]["tx_flow_control"], "auto");
    set(
        &mut s,
        json!({"name": "ether4", "offloads": "gro:off,TSO:off"}),
    );
    let hw = run(&mut s, "interface.hardware", json!({"name": "ether4"}));
    let active = |n: &str| {
        hw["offloads"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["name"] == n)
            .unwrap()["active"]
            .clone()
    };
    assert_eq!(active("GRO"), false);
    assert_eq!(active("TSO"), false);
    assert_eq!(active("GSO"), true);
    set(
        &mut s,
        json!({"name": "ether4", "offloads": {"rx-gro": true}}),
    );
    let cfg = &s.store().running().interfaces;
    let e4 = cfg.values().find(|i| i.name.as_str() == "ether4").unwrap();
    assert_eq!(e4.ethernet.offloads.get("rx-gro"), Some(&true));
    assert_eq!(
        e4.ethernet.offloads.get("tx-tcp-segmentation"),
        Some(&false)
    );
}

fn remote() -> Caller {
    Caller::new(42, "tcp 10.0.0.9:51234").with_principal(Principal::Local)
}

#[test]
fn the_management_port_wants_safe_mode() {
    let mut s = lab();
    s.tick(1_800_000_000);
    run(
        &mut s,
        "ip.address.add",
        json!({"address": "10.0.0.1/24", "interface": "ether1"}),
    );
    let who = remote();
    let change = json!({"name": "ether1", "advertise": "100M-baseT-full"});
    let e = s
        .execute_as(&who, "interface.ethernet.set", &change)
        .unwrap_err()
        .to_string();
    assert!(e.contains("carries this connection (from 10.0.0.9)"), "{e}");
    assert!(
        e.contains("config.safe-mode.enter") && e.contains("force=yes"),
        "{e}"
    );
    // Another port, or offloads on this one: no question asked.
    s.execute_as(
        &who,
        "interface.ethernet.set",
        &json!({"name": "ether2", "advertise": "all"}),
    )
    .unwrap();
    s.execute_as(
        &who,
        "interface.ethernet.set",
        &json!({"name": "ether1", "offloads": "gro:off"}),
    )
    .unwrap();
    // From the router itself (the GUI lab, the local terminal) neither.
    let mut local = lab();
    run(
        &mut local,
        "ip.address.add",
        json!({"address": "10.0.0.1/24", "interface": "ether1"}),
    );
    set(&mut local, change.clone());

    // In Safe Mode it goes through, and the connection closing undoes it.
    s.execute_as(&who, "config.safe-mode.enter", &json!({}))
        .unwrap();
    let r = s
        .execute_as(&who, "interface.ethernet.set", &change)
        .unwrap();
    assert!(
        r["warnings"][0].as_str().unwrap().contains("Safe Mode"),
        "{r}"
    );
    assert_eq!(monitor(&mut s, "ether1")["rate"], "100Mbps");
    s.hang_up(who.id);
    assert_eq!(
        monitor(&mut s, "ether1")["rate"],
        "1Gbps",
        "undone with the connection"
    );

    // force: the operator's call.
    let mut forced = change.clone();
    forced["force"] = json!(true);
    let r = s
        .execute_as(&who, "interface.ethernet.set", &forced)
        .unwrap();
    assert!(r["warnings"][0].as_str().unwrap().contains("forced"), "{r}");
    // Behind a VLAN on the port it is the same port.
    let mut v = lab();
    run(
        &mut v,
        "interface.vlan.add",
        json!({"name": "mgmt", "parent": "ether3", "vlan_id": 99}),
    );
    run(
        &mut v,
        "ip.address.add",
        json!({"address": "10.0.0.1/24", "interface": "mgmt"}),
    );
    let e = v
        .execute_as(
            &who,
            "interface.ethernet.set",
            &json!({"name": "ether3", "auto_negotiation": true, "advertise": "all"}),
        )
        .unwrap_err();
    assert!(matches!(e, EngineError::BadParam { .. }), "{e}");
}

#[test]
fn the_sfp_port_shows_its_module() {
    let mut s = lab();
    let m = monitor(&mut s, "ether8");
    assert_eq!(m["port"], "fibre");
    let sfp = &m["sfp"];
    assert_eq!(sfp["module_present"], true, "{m}");
    assert_eq!(sfp["kind"], "SFP/SFP+/SFP28");
    assert_eq!(sfp["vendor_name"], "CoreRouter Lab");
    assert_eq!(sfp["vendor_part_number"], "CR-SFP10G-SR");
    assert_eq!(sfp["wavelength_nm"], 850.0);
    assert_eq!(sfp["compliance"], json!(["10GBASE-SR"]));
    let dom = sfp["dom"].as_array().unwrap();
    let names: Vec<&str> = dom.iter().map(|r| r["name"].as_str().unwrap()).collect();
    assert_eq!(
        names,
        [
            "temperature",
            "supply-voltage",
            "tx-bias-current",
            "tx-power",
            "rx-power"
        ]
    );
    let rx = &dom[4];
    assert_eq!(rx["unit"], "dBm");
    assert_eq!(rx["level"], "ok");
    assert!(rx["limits"]["low_alarm"].as_f64().unwrap() < -13.0);
    assert_eq!(sfp["alerts"], json!([]));
    // A copper port has no cage: null with the reason.
    let c = monitor(&mut s, "ether1");
    assert_eq!(c["sfp"], Value::Null);
    assert!(c["sfp_reason"].as_str().unwrap().contains("copper"), "{c}");
    // Disabled: the laser is off and TX power reads "no light".
    run(
        &mut s,
        "interface.set",
        json!({"name": "ether8", "disabled": true}),
    );
    let off = monitor(&mut s, "ether8");
    let tx = &off["sfp"]["dom"][3];
    assert_eq!(tx["value"], -40.0);
    assert_eq!(tx["level"], "low-alarm");
    assert_eq!(
        off["sfp"]["alerts"],
        json!([]),
        "the laser is off on purpose"
    );
}

/// A platform without Ethernet support at all (the trait defaults).
struct Bare(VirtualHal);

/// The lab, with a weak signal on ether8's module.
struct Weak(VirtualHal);

macro_rules! delegate {
    ($t:ty) => {
        impl Hal for $t {
            fn describe(&self) -> String {
                stringify!($t).into()
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
            fn ethernet_monitor(&mut self, name: &IfName) -> Result<EthernetMonitor, HalError> {
                if stringify!($t) == "Bare" {
                    return Err(HalError::Unsupported("no ethtool here".into()));
                }
                self.0.ethernet_monitor(name)
            }
            fn sfp_module(&mut self, name: &IfName) -> Result<SfpModule, HalError> {
                if stringify!($t) == "Bare" {
                    return Err(HalError::Unsupported("no module EEPROM here".into()));
                }
                self.0.sfp_module(name)?;
                let (a0, a2) = sff::lab_sfp_plus("WEAK1", 45.0, -2.4, -16.0);
                Ok(sff::decode(&a0, Some(&a2)))
            }
        }
    };
}
delegate!(Bare);
delegate!(Weak);

#[test]
fn a_weak_signal_is_an_alert() {
    let mut s = Session::new(Box::new(Weak(VirtualHal::default())));
    let m = monitor(&mut s, "ether8");
    assert_eq!(
        m["sfp"]["alerts"],
        json!(["rx-power -16.00 dBm (low-alarm)"]),
        "{m}"
    );
    assert_eq!(m["sfp"]["dom"][4]["level"], "low-alarm");
}

#[test]
fn a_platform_without_ethtool_says_so() {
    let mut s = Session::new(Box::new(Bare(VirtualHal::new(2))));
    s.set_runner(Arc::new(Threads));
    let e = fails(
        &mut s,
        "interface.ethernet.set",
        json!({"name": "ether1", "auto_negotiation": true}),
    );
    assert!(
        e.contains("does not let CoreRouter read its link: no ethtool here"),
        "{e}"
    );
    let e = fails(
        &mut s,
        "interface.ethernet.cable-test",
        json!({"name": "ether1"}),
    );
    assert!(e.contains("not supported"), "{e}");
    let m = monitor(&mut s, "ether1");
    assert_eq!(m["available"], false);
    assert_eq!(m["sfp"], Value::Null);
}

#[test]
fn cable_test_runs_as_a_task_with_a_result_per_pair() {
    let mut s = lab();
    let e = fails(
        &mut s,
        "interface.ethernet.cable-test",
        json!({"name": "ether1"}),
    );
    assert!(
        e.contains("disabled") && e.contains("background tasks"),
        "{e}"
    );
    s.set_runner(Arc::new(Threads));
    let e = fails(
        &mut s,
        "interface.ethernet.cable-test",
        json!({"name": "ether8"}),
    );
    assert!(e.contains("not supported") && e.contains("fibre"), "{e}");
    let rev = s.store().current_revision();
    let started = run(
        &mut s,
        "interface.ethernet.cable-test",
        json!({"name": "ether7"}),
    );
    let id = started["id"].as_u64().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let done = loop {
        let p = run(&mut s, "tool.task.poll", json!({"id": id, "text": true}));
        if p["done"] == true {
            break p;
        }
        assert!(Instant::now() < deadline, "the test never finished: {p}");
        thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(done["state"], "done", "{done}");
    assert_eq!(done["kind"], "cable-test");
    let pairs: Vec<(String, String)> = done["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e["pair"].as_str().unwrap().into(),
                e["status"].as_str().unwrap().into(),
            )
        })
        .collect();
    assert_eq!(pairs.len(), 4);
    assert_eq!(pairs[2], ("C".into(), "short".into()));
    assert_eq!(done["summary"]["status"], "fault");
    assert_eq!(done["summary"]["cable_pairs"], "ok,ok,short:23.5,ok");
    let text = done["summary_lines"].to_string();
    assert!(text.contains("cable-pairs: ok,ok,short:23.5,ok"), "{text}");
    assert_eq!(s.store().current_revision(), rev, "a query: no revision");

    // The management port: refused outside Safe Mode.
    run(
        &mut s,
        "ip.address.add",
        json!({"address": "10.0.0.1/24", "interface": "ether1"}),
    );
    let e = s
        .execute_as(
            &remote(),
            "interface.ethernet.cable-test",
            &json!({"name": "ether1"}),
        )
        .unwrap_err()
        .to_string();
    assert!(e.contains("cable test takes its link down"), "{e}");
}

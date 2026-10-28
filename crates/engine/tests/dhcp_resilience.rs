//! G4.7c — DHCP client resilience in the lab, on a simulated clock: the
//! lease remembered across restarts (INIT-REBOOT), the fallback address and
//! check-gateway.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::sync::Arc;

use corerouter_engine::{ConfigStorage, MemoryStorage, Session};
use corerouter_hal::VirtualHal;
use corerouter_proto_dhcp::lab::{Knobs, LabServer};
use serde_json::{Value, json};

struct Lab {
    s: Session,
    server: Arc<LabServer>,
    storage: MemoryStorage,
    now: u64,
}

impl Lab {
    fn new(knobs: Knobs) -> Self {
        Self::boot(knobs, MemoryStorage::default(), 1_000_000)
    }

    /// A session on `storage` (another "boot" of the same router) whose
    /// wall clock reads `unix`.
    fn boot(knobs: Knobs, storage: MemoryStorage, unix: u64) -> Self {
        let server = Arc::new(LabServer::new(knobs));
        let hal = VirtualHal::default().with_dhcp_server(server.clone());
        let mut s = Session::with_storage(Box::new(hal), Box::new(storage.clone()));
        s.tick(unix);
        Self {
            s,
            server,
            storage,
            now: 0,
        }
    }

    fn ok(&mut self, id: &str, p: Value) -> Value {
        self.s
            .execute(id, &p)
            .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
    }

    fn fails(&mut self, id: &str, p: Value, needle: &str) {
        let before = self.s.store().candidate().clone();
        let err = self.s.execute(id, &p).unwrap_err().to_string();
        assert!(err.contains(needle), "{id} {p}: '{err}' lacks '{needle}'");
        assert_eq!(self.s.store().candidate(), &before);
    }

    fn run(&mut self, ms: u64) {
        let end = self.now + ms;
        while self.now <= end {
            self.s.dhcp_service(self.now);
            self.now += 250;
        }
    }

    fn client(&mut self) -> Value {
        self.ok("ip.dhcp-client.list", Value::Null)[0].clone()
    }

    fn events(&mut self) -> Vec<String> {
        self.ok("ip.dhcp-client.history", Value::Null)["events"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                format!(
                    "{}: {}",
                    e["event"].as_str().unwrap(),
                    e["message"].as_str().unwrap()
                )
            })
            .collect()
    }

    fn addresses(&mut self) -> Vec<String> {
        self.ok("ip.address.list", Value::Null)
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["address"].as_str().unwrap().to_owned())
            .collect()
    }

    fn defaults(&mut self) -> Vec<Value> {
        self.ok("ip.route.list", Value::Null)
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["dst_address"] == "0.0.0.0/0")
            .cloned()
            .collect()
    }
}

fn mine() -> String {
    let ip = LabServer::address_for(&"ether1".parse().unwrap(), [2, 0, 0, 0, 0, 1]);
    format!("{ip}/24")
}

/// A router that got a lease, then "reboots" `secs` later on the same
/// storage, with the lab server set to `knobs`.
fn rebooted(knobs: Knobs, secs: u64) -> Lab {
    let mut l = Lab::new(Knobs::default());
    l.ok("ip.dhcp-client.add", json!({"interface": "ether1"}));
    l.run(1_000);
    assert_eq!(l.client()["status"], "bound");
    assert_eq!(l.client()["remembered"], mine());
    let saved = l
        .storage
        .clone()
        .load_state("dhcp-leases")
        .unwrap()
        .unwrap();
    assert!(saved.contains(&mine()), "{saved}");
    // Outside the revisions: the saved config does not have it.
    assert!(
        !l.storage
            .get(corerouter_engine::Slot::Current)
            .unwrap()
            .contains(&mine())
    );
    let storage = l.storage.clone();
    drop(l);
    Lab::boot(knobs, storage, 1_000_000 + secs)
}

#[test]
fn a_restart_asks_for_the_remembered_lease_with_init_reboot() {
    let mut l = rebooted(Knobs::default(), 60);
    l.run(1_000);
    let c = l.client();
    assert_eq!(c["status"], "bound", "{c}");
    assert_eq!(c["address"], mine());
    let ev = l.events();
    assert!(
        ev.iter()
            .any(|e| e.starts_with("rebooting: asking to keep")),
        "{ev:?}"
    );
    // No DISCOVER/OFFER: the server confirmed the address directly.
    assert!(
        !ev.iter()
            .any(|e| e.starts_with("searching") || e.starts_with("offered")),
        "{ev:?}"
    );
}

#[test]
fn a_silent_network_after_a_restart_keeps_the_unexpired_lease() {
    let mut l = rebooted(
        Knobs {
            silent: true,
            ..Knobs::default()
        },
        60,
    );
    l.run(5_000);
    assert_eq!(l.client()["status"], "requesting");
    assert!(!l.addresses().contains(&mine()));
    l.run(15_000);
    let c = l.client();
    // RFC 2131 §3.2: used for the rest of the lease (600 s - 60 s - ~13 s),
    // renewing at the old T1.
    assert_eq!(c["address"], mine(), "{c}");
    assert_eq!(c["status"], "bound");
    assert!(c["expires_after_secs"].as_u64().unwrap() < 540);
    l.run(240_000);
    assert_eq!(l.client()["status"], "renewing");
    assert!(l.addresses().contains(&mine()));
    assert!(
        l.events()
            .iter()
            .any(|e| e.contains("no server answered: using the remembered lease"))
    );
}

#[test]
fn an_expired_remembered_lease_is_not_used_without_a_server() {
    let mut l = rebooted(
        Knobs {
            silent: true,
            ..Knobs::default()
        },
        3_600,
    );
    l.run(20_000);
    assert_eq!(l.client()["status"], "searching");
    assert!(!l.addresses().contains(&mine()));
}

#[test]
fn a_nak_forgets_the_remembered_lease() {
    let mut l = rebooted(
        Knobs {
            nak: true,
            ..Knobs::default()
        },
        60,
    );
    l.run(1_000);
    assert!(l.events().iter().any(|e| e.starts_with("nak:")));
    assert_eq!(l.client()["remembered"], Value::Null);
    let saved = l
        .storage
        .clone()
        .load_state("dhcp-leases")
        .unwrap()
        .unwrap();
    assert!(!saved.contains(&mine()), "{saved}");
}

#[test]
fn release_and_remove_forget_the_lease() {
    let mut l = Lab::new(Knobs::default());
    l.ok("ip.dhcp-client.add", json!({"interface": "ether1"}));
    l.run(1_000);
    l.server.set(|k| k.silent = true);
    l.ok("ip.dhcp-client.release", json!({"id": "*1"}));
    assert_eq!(l.client()["remembered"], Value::Null);
    l.server.set(|k| k.silent = false);
    l.run(20_000);
    assert_eq!(l.client()["remembered"], mine());
    l.ok("ip.dhcp-client.remove", json!({"id": "*1"}));
    l.run(250);
    let saved = l
        .storage
        .clone()
        .load_state("dhcp-leases")
        .unwrap()
        .unwrap();
    assert!(!saved.contains(&mine()), "{saved}");
}

#[test]
fn a_damaged_lease_file_is_ignored() {
    let mut storage = MemoryStorage::default();
    storage.save_state("dhcp-leases", "{not json").unwrap();
    let mut l = Lab::boot(Knobs::default(), storage, 1_000_000);
    l.ok("ip.dhcp-client.add", json!({"interface": "ether1"}));
    l.run(1_000);
    assert_eq!(l.client()["status"], "bound");
    // A well-formed file with a hostile ACK is ignored too.
    let mut storage = MemoryStorage::default();
    storage
        .save_state(
            "dhcp-leases",
            r#"{"leases":[{"client":"*1","interface":"ether1","mac":[2,0,0,0,0,1],"address":"100.64.1.99/24","server":"100.64.1.1","ack":"ff00ff"}]}"#,
        )
        .unwrap();
    let mut l = Lab::boot(Knobs::default(), storage, 1_000_000);
    l.ok("ip.dhcp-client.add", json!({"interface": "ether1"}));
    l.run(1_000);
    assert_eq!(l.client()["address"], mine());
}

#[test]
fn the_fallback_address_covers_a_silent_server() {
    let mut l = Lab::new(Knobs {
        silent: true,
        ..Knobs::default()
    });
    l.ok(
        "ip.dhcp-client.add",
        json!({"interface": "ether1", "fallback_address": "192.168.100.2/24", "fallback_timeout": 5}),
    );
    l.run(4_000);
    assert!(!l.addresses().contains(&"192.168.100.2/24".to_owned()));
    l.run(2_000);
    assert!(l.addresses().contains(&"192.168.100.2/24".to_owned()));
    let c = l.client();
    assert_eq!(c["fallback_active"], true);
    assert_eq!(c["status"], "searching");
    assert!(
        l.events()
            .iter()
            .any(|e| e.starts_with("fallback: no lease after 5 s"))
    );
    // A server comes: the lease replaces the fallback address.
    l.server.set(|k| k.silent = false);
    l.run(70_000);
    let addrs = l.addresses();
    assert!(addrs.contains(&mine()), "{addrs:?}");
    assert!(!addrs.contains(&"192.168.100.2/24".to_owned()));
    assert_eq!(l.client()["fallback_active"], false);
    // Clearing the setting while it is up takes it down.
    l.server.set(|k| k.silent = true);
    l.ok("ip.dhcp-client.release", json!({"id": "*1"}));
    l.run(6_000);
    assert!(l.addresses().contains(&"192.168.100.2/24".to_owned()));
    l.ok(
        "ip.dhcp-client.set",
        json!({"id": "*1", "fallback_address": ""}),
    );
    l.run(250);
    assert!(!l.addresses().contains(&"192.168.100.2/24".to_owned()));
}

#[test]
fn check_gateway_arp_withholds_the_routes_while_the_gateway_is_silent() {
    let mut l = Lab::new(Knobs::default());
    // A backup default route, distance 10, through a second uplink.
    l.ok(
        "ip.address.add",
        json!({"address": "10.0.0.2/24", "interface": "ether2"}),
    );
    l.ok(
        "ip.route.add",
        json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1", "distance": 10}),
    );
    l.ok(
        "ip.dhcp-client.add",
        json!({"interface": "ether1", "check_gateway": "arp"}),
    );
    l.run(1_000);
    assert_eq!(l.client()["gateway_status"], "up");
    let d = l.defaults();
    assert_eq!(d[0]["dynamic"], true);
    assert_eq!(d[0]["active"], true);
    // G1.27: the route shows its check-gateway.
    assert_eq!(d[0]["check_gateway"]["method"], "arp");
    assert_eq!(d[0]["check_gateway"]["state"], "up");
    assert_eq!(d[0]["origin"], "dhcp");

    l.server.set(|k| k.gateway_down = true);
    // Two unanswered checks, 10 s apart.
    l.run(25_000);
    assert_eq!(l.client()["gateway_status"], "down");
    let d = l.defaults();
    let dhcp = d.iter().find(|r| r["dynamic"] == true).unwrap();
    assert_eq!(dhcp["active"], false, "{d:?}");
    assert!(
        dhcp["reason"]
            .as_str()
            .unwrap()
            .contains("check-gateway=arp")
    );
    // G1.27: how long ago it failed.
    assert_eq!(dhcp["reason_id"], "check-gateway", "{dhcp}");
    assert!(
        dhcp["reason"].as_str().unwrap().contains(" s ago"),
        "{dhcp}"
    );
    assert_eq!(dhcp["check_gateway"]["state"], "down");
    assert_eq!(dhcp["state"], "inactive");
    // G1.27b: the detail names the client and the check.
    let det = l.ok("ip.route.detail", json!({"key": dhcp["key"]}));
    assert_eq!(det["source"]["kind"], "dhcp");
    assert!(
        det["source"]["text"]
            .as_str()
            .unwrap()
            .starts_with("DHCP client on ether1"),
        "{det}"
    );
    assert!(
        det["check_gateway"]["misses"].as_u64().unwrap() >= 2,
        "{det}"
    );
    assert!(
        det["check_gateway"]["down_secs"].as_u64().is_some(),
        "{det}"
    );
    let backup = d.iter().find(|r| r["dynamic"] == false).unwrap();
    assert_eq!(backup["active"], true, "{d:?}");
    assert!(
        l.events()
            .iter()
            .any(|e| e.starts_with("gateway: gateway 100.64.1.1 did not answer 2 arp checks"))
    );

    // The first answer brings the routes back.
    l.server.set(|k| k.gateway_down = false);
    l.run(11_000);
    assert_eq!(l.client()["gateway_status"], "up");
    let d = l.defaults();
    assert_eq!(
        d.iter().find(|r| r["dynamic"] == true).unwrap()["active"],
        true
    );
    assert!(l.events().iter().any(|e| e.contains("answers again")));

    // Turned off: nothing is checked.
    l.ok(
        "ip.dhcp-client.set",
        json!({"id": "*1", "check_gateway": "none"}),
    );
    l.run(250);
    assert_eq!(l.client()["gateway_status"], "unchecked");
}

#[test]
fn check_gateway_ping_sees_the_lab_gateway() {
    let mut l = Lab::new(Knobs::default());
    l.ok(
        "ip.dhcp-client.add",
        json!({"interface": "ether1", "check_gateway": "ping"}),
    );
    l.run(30_000);
    let c = l.client();
    assert_eq!(c["gateway_status"], "up", "{c}");
    assert_eq!(c["check_gateway"], "ping");
}

#[test]
fn resilience_settings_are_validated() {
    let mut l = Lab::new(Knobs::default());
    l.fails(
        "ip.dhcp-client.add",
        json!({"interface": "ether1", "check_gateway": "bfd"}),
        "arp or ping (bfd is for static routes)",
    );
    l.fails(
        "ip.dhcp-client.add",
        json!({"interface": "ether1", "check_gateway": "icmp"}),
        "expected none, arp, ping or bfd",
    );
    for bad in [
        "10.0.0.0/24",
        "10.0.0.255/24",
        "0.0.0.0/8",
        "224.0.0.1/4",
        "nope",
        "10.0.0.1",
    ] {
        l.fails(
            "ip.dhcp-client.add",
            json!({"interface": "ether1", "fallback_address": bad}),
            "fallback_address",
        );
    }
    for bad in [0, 4, 3_601] {
        l.fails(
            "ip.dhcp-client.add",
            json!({"interface": "ether1", "fallback_timeout": bad}),
            "5..=3600",
        );
    }
    l.ok(
        "ip.dhcp-client.add",
        json!({"interface": "ether1", "fallback_address": "192.168.100.2/24", "fallback_timeout": 60}),
    );
    let c = l.client();
    assert_eq!(c["fallback_address"], "192.168.100.2/24");
    assert_eq!(c["fallback_timeout"], 60);
    assert_eq!(c["check_gateway"], "none");
}

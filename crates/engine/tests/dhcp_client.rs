//! G4.7a — `/ip dhcp-client`: commands (success, validation, rollback) and
//! the clients at run time against the lab's simulated server, on a
//! simulated clock (`Session::dhcp_service(ms)`).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use corerouter_engine::Session;
use corerouter_hal::dhcp::{DhcpPort, SharedResponder};
use corerouter_hal::{Features, Hal, HalError, LinkInfo, LinkState, SharedProber, VirtualHal};
use corerouter_model::{Config, IfName};
use corerouter_proto_dhcp::lab::{Knobs, LabServer};
use serde_json::{Value, json};

/// The lab, recording what the data plane was last told to run; `fail`
/// makes every apply fail (to see commands roll back).
struct Watch {
    inner: VirtualHal,
    applied: Arc<Mutex<Config>>,
    fail: Arc<AtomicBool>,
}

impl Hal for Watch {
    fn describe(&self) -> String {
        self.inner.describe()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.inner.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        if self.fail.load(Ordering::Relaxed) {
            return Err(HalError::Rejected("test: apply fails".into()));
        }
        self.inner.apply(from, to)?;
        *self.applied.lock().unwrap() = to.clone();
        Ok(())
    }
    fn poll(&mut self) -> Vec<LinkState> {
        self.inner.poll()
    }
    fn now_unix(&self) -> Option<u64> {
        None
    }
    fn features(&self) -> Features {
        self.inner.features()
    }
    fn prober(&self) -> Result<SharedProber, String> {
        self.inner.prober()
    }
    fn dhcp_port(&mut self, name: &IfName) -> Result<Box<dyn DhcpPort>, HalError> {
        self.inner.dhcp_port(name)
    }
    fn offer_dhcp_lab_server(&mut self, server: SharedResponder) {
        self.inner.offer_dhcp_lab_server(server);
    }
}

struct Lab {
    s: Session,
    server: Arc<LabServer>,
    applied: Arc<Mutex<Config>>,
    fail: Arc<AtomicBool>,
    now: u64,
}

impl Lab {
    fn new(knobs: Knobs) -> Self {
        let server = Arc::new(LabServer::new(knobs));
        let applied = Arc::new(Mutex::new(Config::default()));
        let fail = Arc::new(AtomicBool::new(false));
        let hal = Watch {
            inner: VirtualHal::default().with_dhcp_server(server.clone()),
            applied: applied.clone(),
            fail: fail.clone(),
        };
        let mut s = Session::new(Box::new(hal));
        s.tick(1_000_000);
        Self {
            s,
            server,
            applied,
            fail,
            now: 0,
        }
    }

    fn ok(&mut self, id: &str, p: Value) -> Value {
        self.s
            .execute(id, &p)
            .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
    }

    /// The command fails, the message contains `needle`, and nothing changed.
    fn fails(&mut self, id: &str, p: Value, needle: &str) {
        let before = self.s.store().candidate().clone();
        let rev = self.s.store().current_revision();
        let err = self.s.execute(id, &p).unwrap_err().to_string();
        assert!(err.contains(needle), "{id} {p}: '{err}' lacks '{needle}'");
        assert_eq!(
            self.s.store().candidate(),
            &before,
            "{id} left changes behind"
        );
        assert_eq!(self.s.store().current_revision(), rev);
    }

    /// Run the service every 250 ms for `ms`.
    fn run(&mut self, ms: u64) {
        let end = self.now + ms;
        while self.now <= end {
            self.s.dhcp_service(self.now);
            self.now += 250;
        }
    }

    fn client(&mut self, id: &str) -> Value {
        let rows = self.ok("ip.dhcp-client.list", Value::Null);
        rows.as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .cloned()
            .unwrap_or_else(|| panic!("{id} not listed: {rows}"))
    }

    fn add(&mut self, p: Value) -> String {
        self.ok("ip.dhcp-client.add", p)["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn routes(&mut self) -> Vec<Value> {
        self.ok("ip.route.list", Value::Null)
            .as_array()
            .unwrap()
            .clone()
    }

    fn dynamic_addresses(&mut self) -> Vec<Value> {
        self.ok("ip.address.list", Value::Null)
            .as_array()
            .unwrap()
            .iter()
            .filter(|a| a["dynamic"] == true)
            .cloned()
            .collect()
    }

    /// Addresses and routes the data plane holds.
    fn data_plane(&self) -> (Vec<String>, Vec<String>) {
        let c = self.applied.lock().unwrap();
        (
            c.ip.addresses
                .iter()
                .map(|a| format!("{}@{}", a.address, a.interface))
                .collect(),
            c.ip.routes
                .iter()
                .map(|r| format!("{} via {}", r.dst_address, r.gateway))
                .collect(),
        )
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
}

fn mine() -> String {
    // The address the lab gives ether1 (MAC 02:00:00:00:00:01).
    LabServer::address_for(&"ether1".parse().unwrap(), [2, 0, 0, 0, 0, 1]).to_string()
}

#[test]
fn a_lab_client_gets_a_lease_and_the_data_plane_runs_it() {
    let mut l = Lab::new(Knobs::default());
    let id = l.add(json!({"interface": "ether1", "comment": "WAN"}));
    let c = l.client(&id);
    assert_eq!(c["status"], "stopped", "nothing runs before the service");
    l.run(1_000);
    let c = l.client(&id);
    assert_eq!(c["status"], "bound", "{c}");
    assert_eq!(c["address"], format!("{}/24", mine()));
    assert_eq!(c["gateway"], "100.64.1.1");
    assert_eq!(c["dhcp_server"], "100.64.1.1");
    assert_eq!(c["primary_dns"], "100.64.1.1");
    assert_eq!(c["primary_ntp"], "100.64.1.1");
    assert_eq!(c["secondary_dns"], Value::Null);
    assert_eq!(c["domain"], "lab.test");
    assert_eq!(c["lease_time"], "10m");
    assert_eq!(c["expires_after"], "9m59s");
    assert_eq!(c["flags"], "");

    let dynamic = l.dynamic_addresses();
    assert_eq!(dynamic.len(), 1);
    assert_eq!(dynamic[0]["flags"], "D");
    assert_eq!(dynamic[0]["interface"], "ether1");
    // Option 121 came, so it decides the routes (option 3 is ignored).
    let routes = l.routes();
    let default = routes
        .iter()
        .find(|r| r["dst_address"] == "0.0.0.0/0")
        .unwrap();
    assert_eq!(default["flags"], "ADS");
    assert_eq!(default["gateway"], "100.64.1.1%ether1");
    assert_eq!(default["dynamic"], true);
    assert!(
        routes
            .iter()
            .any(|r| r["dst_address"] == "10.200.0.0/16" && r["gateway"] == "100.64.1.254%ether1")
    );
    assert!(
        routes
            .iter()
            .any(|r| r["dst_address"] == "100.64.1.0/24" && r["flags"] == "ADC")
    );

    let (addrs, kernel_routes) = l.data_plane();
    assert!(
        addrs.contains(&format!("{}/24@ether1", mine())),
        "{addrs:?}"
    );
    assert!(
        kernel_routes.contains(&"0.0.0.0/0 via 100.64.1.1%ether1".to_owned()),
        "{kernel_routes:?}"
    );

    assert_eq!(
        l.s.dhcp_peer_dns(),
        vec!["100.64.1.1".parse::<std::net::Ipv4Addr>().unwrap()]
    );
    // G4.1a: the router's resolver sees them as RouterOS `dynamic-servers`.
    assert_eq!(
        l.ok("ip.dns.get", json!({}))["dynamic_servers"],
        json!(["100.64.1.1"])
    );
    let opts = l.ok("ip.dhcp-client.options", json!({"id": id}));
    let opts = opts["options"].as_array().unwrap();
    assert!(opts.iter().any(|o| o["code"] == 121
        && o["name"] == "classless-static-route"
        && o["value"] == "0.0.0.0/0 via 100.64.1.1, 10.200.0.0/16 via 100.64.1.254"));
    assert!(opts.iter().any(|o| o["code"] == 51 && o["value"] == "600s"));
    let ev = l.events();
    assert!(ev.iter().any(|e| e.starts_with("bound: got")), "{ev:?}");
    // Nothing of the lease is in the config.
    assert!(l.s.store().running().ip.addresses.is_empty());
}

#[test]
fn a_commit_keeps_the_lease_in_the_data_plane() {
    let mut l = Lab::new(Knobs::default());
    l.add(json!({"interface": "ether1"}));
    l.run(1_000);
    l.ok(
        "ip.address.add",
        json!({"address": "192.168.88.1/24", "interface": "ether2"}),
    );
    let (addrs, routes) = l.data_plane();
    assert!(
        addrs.contains(&format!("{}/24@ether1", mine())),
        "{addrs:?}"
    );
    assert!(addrs.contains(&"192.168.88.1/24@ether2".to_owned()));
    assert!(routes.iter().any(|r| r.starts_with("0.0.0.0/0")));
}

#[test]
fn add_default_route_modes() {
    // No option 121: `yes` takes the router option.
    let mut l = Lab::new(Knobs {
        classless: false,
        ..Knobs::default()
    });
    let id = l.add(json!({"interface": "ether1", "default_route_distance": 5}));
    l.run(1_000);
    let routes: Vec<Value> = l
        .routes()
        .into_iter()
        .filter(|r| r["dynamic"] == true && r["connected"] == false)
        .collect();
    assert_eq!(routes.len(), 1, "{routes:?}");
    assert_eq!(routes[0]["dst_address"], "0.0.0.0/0");
    assert_eq!(routes[0]["distance"], 5);
    // `no`: no route at all; applied at once to the running lease.
    l.ok(
        "ip.dhcp-client.set",
        json!({"id": id, "add_default_route": "no"}),
    );
    l.run(250);
    assert!(
        l.routes()
            .iter()
            .all(|r| r["dynamic"] == false || r["connected"] == true)
    );
    let (_, kernel) = l.data_plane();
    assert!(kernel.is_empty(), "{kernel:?}");
    // 121 + special-classless: the classless routes and option 3's default,
    // which 121 already has, so one default route and a note.
    let mut l = Lab::new(Knobs::default());
    let id = l.add(json!({"interface": "ether1", "add_default_route": "special-classless"}));
    l.run(1_000);
    let c = l.client(&id);
    assert_eq!(c["routes"].as_array().unwrap().len(), 2, "{c}");
    assert!(c["notes"][0].as_str().unwrap().contains("option 121 wins"));
}

#[test]
fn a_static_route_holds_its_place() {
    let mut l = Lab::new(Knobs {
        classless: false,
        ..Knobs::default()
    });
    l.ok(
        "ip.address.add",
        json!({"address": "10.0.0.2/24", "interface": "ether2"}),
    );
    l.ok(
        "ip.route.add",
        json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}),
    );
    let id = l.add(json!({"interface": "ether1"}));
    l.run(1_000);
    // Same distance as the static one: the kernel takes one, the static.
    let defaults: Vec<Value> = l
        .routes()
        .into_iter()
        .filter(|r| r["dst_address"] == "0.0.0.0/0")
        .collect();
    assert_eq!(defaults.len(), 1, "{defaults:?}");
    assert_eq!(defaults[0]["static"], true);
    assert_eq!(defaults[0]["dynamic"], false);
    // A backup: distance 2 is listed, not active.
    l.ok(
        "ip.dhcp-client.set",
        json!({"id": id, "default_route_distance": 2}),
    );
    l.run(250);
    let defaults: Vec<Value> = l
        .routes()
        .into_iter()
        .filter(|r| r["dst_address"] == "0.0.0.0/0")
        .collect();
    assert_eq!(defaults.len(), 2);
    assert_eq!(defaults[1]["flags"], "DS");
    assert!(
        defaults[1]["reason"]
            .as_str()
            .unwrap()
            .contains("lower distance")
    );
}

#[test]
fn renew_and_release() {
    let mut l = Lab::new(Knobs::default());
    let id = l.add(json!({"interface": "ether1"}));
    l.run(60_000);
    let r = l.ok("ip.dhcp-client.renew", json!({"id": id}));
    assert_eq!(r["status"], "bound");
    assert_eq!(l.client(&id)["expires_after"], "10m");
    let r = l.ok("ip.dhcp-client.release", json!({"id": id}));
    // The lab answers at once: acquiring again, probing the address.
    assert_eq!(r["status"], "requesting");
    assert!(l.dynamic_addresses().is_empty());
    l.run(1_000);
    assert_eq!(l.client(&id)["status"], "bound");
    let ev = l.events();
    assert!(ev.iter().any(|e| e.starts_with("renewed:")), "{ev:?}");
    assert!(
        ev.iter()
            .any(|e| e.starts_with("lost:") && e.ends_with("released")),
        "{ev:?}"
    );
}

#[test]
fn losing_the_server_loses_the_lease_at_expiry() {
    let mut l = Lab::new(Knobs::default());
    let id = l.add(json!({"interface": "ether1"}));
    l.run(1_000);
    l.server.set(|k| k.silent = true);
    l.run(300_000);
    assert_eq!(l.client(&id)["status"], "renewing");
    l.run(225_000);
    assert_eq!(l.client(&id)["status"], "rebinding");
    assert_eq!(l.dynamic_addresses().len(), 1, "still ours");
    l.run(75_000);
    assert_eq!(l.client(&id)["status"], "searching");
    assert!(l.dynamic_addresses().is_empty());
    let (addrs, routes) = l.data_plane();
    assert!(
        addrs.is_empty() && routes.is_empty(),
        "{addrs:?} {routes:?}"
    );
    assert!(l.events().iter().any(|e| e.contains("lease expired")));
    // The server comes back: a new lease within one DISCOVER backoff.
    l.server.set(|k| k.silent = false);
    l.run(70_000);
    assert_eq!(l.client(&id)["status"], "bound");
}

#[test]
fn a_nak_while_renewing_drops_the_lease() {
    let mut l = Lab::new(Knobs::default());
    let id = l.add(json!({"interface": "ether1"}));
    l.run(1_000);
    l.server.set(|k| k.nak = true);
    l.run(300_000);
    assert_eq!(l.client(&id)["status"], "searching");
    assert!(l.dynamic_addresses().is_empty());
    assert!(
        l.events()
            .iter()
            .any(|e| e.starts_with("nak: 100.64.1.1 said NAK: lab"))
    );
}

#[test]
fn servers_outside_allowed_servers_are_ignored() {
    let mut l = Lab::new(Knobs::default());
    let id =
        l.add(json!({"interface": "ether1", "allowed_servers": "192.0.2.1,AA:BB:CC:DD:EE:FF"}));
    l.run(10_000);
    assert_eq!(l.client(&id)["status"], "searching");
    assert!(l.dynamic_addresses().is_empty());
    let (_, routes) = l.data_plane();
    assert!(routes.is_empty(), "never a route from a refused server");
    let refused: Vec<String> = l
        .events()
        .into_iter()
        .filter(|e| e.starts_with("refused"))
        .collect();
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert!(refused[0].contains("100.64.1.1 (02:DC:00:00:00:01)"));
    // Allowing the lab server's MAC is enough.
    l.ok(
        "ip.dhcp-client.set",
        json!({"id": id, "allowed_servers": ["02:dc:00:00:00:01"]}),
    );
    l.run(70_000);
    assert_eq!(l.client(&id)["status"], "bound");
}

#[test]
fn an_address_in_use_is_declined() {
    let mut l = Lab::new(Knobs {
        squatter: Some([0xaa; 6]),
        ..Knobs::default()
    });
    let id = l.add(json!({"interface": "ether1"}));
    l.run(5_000);
    assert_eq!(l.client(&id)["status"], "searching");
    assert!(
        l.events()
            .iter()
            .any(|e| e.starts_with("declined:") && e.contains("AA:AA:AA:AA:AA:AA"))
    );
    assert!(l.dynamic_addresses().is_empty());
}

#[test]
fn disabling_removing_or_disabling_the_interface_drops_the_lease() {
    let mut l = Lab::new(Knobs::default());
    let id = l.add(json!({"interface": "ether1"}));
    l.run(1_000);
    l.ok("ip.dhcp-client.set", json!({"id": id, "disabled": true}));
    // Gone from the data plane with the commit, before the service runs.
    assert!(l.data_plane().0.is_empty());
    assert!(l.dynamic_addresses().is_empty());
    l.run(250);
    let c = l.client(&id);
    assert_eq!(
        (c["status"].as_str(), c["flags"].as_str()),
        (Some("stopped"), Some("X"))
    );
    assert!(l.events().iter().any(|e| e == "stopped: client disabled"));

    l.ok("ip.dhcp-client.set", json!({"id": id, "disabled": false}));
    l.run(1_000);
    assert_eq!(l.client(&id)["status"], "bound");
    l.ok("interface.set", json!({"name": "ether1", "disabled": true}));
    l.run(250);
    assert_eq!(l.client(&id)["status"], "stopped");
    assert!(l.dynamic_addresses().is_empty());
    l.ok(
        "interface.set",
        json!({"name": "ether1", "disabled": false}),
    );
    l.run(1_000);
    assert_eq!(l.client(&id)["status"], "bound");

    l.ok("ip.dhcp-client.remove", json!({"id": id}));
    assert!(l.data_plane().0.is_empty());
    l.run(250);
    assert!(l.events().iter().any(|e| e == "stopped: client removed"));
}

#[test]
fn transactional_mode_runs_only_what_is_committed() {
    let mut l = Lab::new(Knobs::default());
    l.ok("config.mode.set", json!({"mode": "transactional"}));
    let id = l.add(json!({"interface": "ether1"}));
    l.run(1_000);
    assert_eq!(l.client(&id)["status"], "stopped");
    l.ok("config.commit", json!({}));
    l.run(1_000);
    assert_eq!(l.client(&id)["status"], "bound");
}

#[test]
fn validation_errors_change_nothing() {
    let mut l = Lab::new(Knobs::default());
    l.fails(
        "ip.dhcp-client.add",
        json!({"interface": "ether99"}),
        "does not exist",
    );
    let id = l.add(json!({"interface": "ether1"}));
    l.fails(
        "ip.dhcp-client.add",
        json!({"interface": "ether1"}),
        "already has DHCP client",
    );
    for (p, needle) in [
        (
            json!({"interface": "ether2", "default_route_distance": 0}),
            "1..=255",
        ),
        (
            json!({"interface": "ether2", "default_route_distance": 256}),
            "1..=255",
        ),
        (
            json!({"interface": "ether2", "add_default_route": "maybe"}),
            "special-classless",
        ),
        (
            json!({"interface": "ether2", "allowed_servers": "10.0.0.1,nonsense"}),
            "IPv4 address",
        ),
        (
            json!({"interface": "ether2", "extra_options": "77"}),
            "code:value",
        ),
        (
            json!({"interface": "ether2", "extra_options": "300:0x00"}),
            "1..=254",
        ),
        (
            json!({"interface": "ether2", "extra_options": "53:0x01"}),
            "set by the client",
        ),
        (
            json!({"interface": "ether2", "extra_options": "77:bare"}),
            "in quotes",
        ),
        (
            json!({"interface": "ether2", "host_name": "bad name"}),
            "letters, digits",
        ),
        (
            json!({"interface": "ether2", "default_route_table": "red"}),
            "does not exist",
        ),
        (
            json!({"interface": "ether2", "client_id": "0xabc"}),
            "even number",
        ),
    ] {
        l.fails("ip.dhcp-client.add", p, needle);
    }
    l.fails(
        "ip.dhcp-client.set",
        json!({"id": "*99"}),
        "no DHCP client *99",
    );
    l.fails(
        "ip.dhcp-client.set",
        json!({"id": id, "interface": "ether9"}),
        "does not exist",
    );
    l.fails(
        "ip.dhcp-client.options",
        json!({"id": id}),
        "holds no lease",
    );
    l.fails(
        "interface.remove",
        json!({"name": "ether1"}),
        "physical port",
    );
    // A VLAN with a client cannot go before its client.
    l.ok(
        "interface.vlan.add",
        json!({"name": "wan100", "parent": "ether2", "vlan_id": 100}),
    );
    let vid = l.add(json!({"interface": "wan100"}));
    l.fails(
        "interface.remove",
        json!({"name": "wan100"}),
        "remove DHCP client",
    );
    l.ok("ip.dhcp-client.remove", json!({"id": vid}));
    l.ok("interface.remove", json!({"name": "wan100"}));
    // Dynamic entries are not the operator's to remove (with a static
    // address and route around, so the commands are enabled at all).
    l.ok(
        "ip.address.add",
        json!({"address": "10.0.0.2/24", "interface": "ether3"}),
    );
    l.ok(
        "ip.route.add",
        json!({"dst_address": "10.9.0.0/16", "gateway": "10.0.0.1"}),
    );
    l.run(1_000);
    let addr = l.dynamic_addresses()[0]["id"].as_str().unwrap().to_owned();
    l.fails("ip.address.remove", json!({"id": addr}), "dynamic");
    let rid = l
        .routes()
        .into_iter()
        .find(|r| r["dst_address"] == "0.0.0.0/0")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    l.fails("ip.route.remove", json!({"id": rid}), "dynamic");
}

#[test]
fn a_failed_apply_rolls_the_command_back() {
    let mut l = Lab::new(Knobs::default());
    l.fail.store(true, Ordering::Relaxed);
    l.fails(
        "ip.dhcp-client.add",
        json!({"interface": "ether1"}),
        "test: apply fails",
    );
    assert!(l.s.store().running().ip.dhcp_clients.is_empty());
    l.fail.store(false, Ordering::Relaxed);
    let id = l.add(json!({"interface": "ether1", "host_name": "cpe"}));
    l.fail.store(true, Ordering::Relaxed);
    l.fails(
        "ip.dhcp-client.set",
        json!({"id": id, "host_name": "other"}),
        "test: apply fails",
    );
    l.fails(
        "ip.dhcp-client.remove",
        json!({"id": id}),
        "test: apply fails",
    );
    // A lease the data plane refuses is an error status, retried at renew.
    l.run(1_000);
    let c = l.client(&id);
    assert_eq!(c["status"], "error", "{c}");
    assert!(c["error"].as_str().unwrap().contains("lease not applied"));
    l.fail.store(false, Ordering::Relaxed);
    l.ok("ip.dhcp-client.renew", json!({"id": id}));
    assert_eq!(l.client(&id)["status"], "bound");
    assert_eq!(l.dynamic_addresses().len(), 1);
}

#[test]
fn history_reads_incrementally() {
    let mut l = Lab::new(Knobs::default());
    let id = l.add(json!({"interface": "ether1"}));
    l.run(1_000);
    let all = l.ok("ip.dhcp-client.history", json!({"id": id}));
    let last = all["last_seq"].as_u64().unwrap();
    assert!(last >= 3, "{all}");
    let more = l.ok("ip.dhcp-client.history", json!({"after_seq": last}));
    assert!(more["events"].as_array().unwrap().is_empty());
    l.ok("ip.dhcp-client.renew", json!({"id": id}));
    let more = l.ok("ip.dhcp-client.history", json!({"after_seq": last}));
    assert_eq!(more["events"][0]["event"], "renewed");
    assert_eq!(more["events"][0]["interface"], "ether1");
    assert!(more["events"][0]["time"].as_u64().is_some());
}

#[test]
fn renew_without_a_service_clock_says_why() {
    let mut s = Session::virtual_lab();
    let id = s
        .execute("ip.dhcp-client.add", &json!({"interface": "ether1"}))
        .unwrap()["id"]
        .clone();
    let err = s
        .execute("ip.dhcp-client.renew", &json!({"id": id}))
        .unwrap_err();
    assert!(err.to_string().contains("no service clock"), "{err}");
}

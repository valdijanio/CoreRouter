//! G4.7b — `/ipv6 dhcp-client`, pools and `/ipv6 settings`: commands
//! (success, validation, rollback) and the clients at run time against the
//! lab's simulated DHCPv6 server and Router Advertisements, on a simulated
//! clock (`Session::dhcp_service(ms)`).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use corerouter_engine::Session;
use corerouter_hal::dhcp::{Dhcp6Port, DhcpPort, SharedResponder, SharedResponder6};
use corerouter_hal::{
    Features, Hal, HalError, Learned, LinkInfo, LinkState, SharedProber, VirtualHal,
};
use corerouter_model::{Config, IfName};
use corerouter_proto_dhcp::lab6::{Knobs, LabServer6};
use serde_json::{Value, json};

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
    fn dhcp6_port(&mut self, name: &IfName) -> Result<Box<dyn Dhcp6Port>, HalError> {
        self.inner.dhcp6_port(name)
    }
    fn offer_dhcp6_lab_server(&mut self, server: SharedResponder6) {
        self.inner.offer_dhcp6_lab_server(server);
    }
    fn ipv6_learned(&mut self) -> Result<Vec<Learned>, HalError> {
        self.inner.ipv6_learned()
    }
}

struct Lab {
    s: Session,
    server: Arc<LabServer6>,
    applied: Arc<Mutex<Config>>,
    fail: Arc<AtomicBool>,
    now: u64,
}

impl Lab {
    fn new(knobs: Knobs) -> Self {
        let server = Arc::new(LabServer6::new(knobs));
        let applied = Arc::new(Mutex::new(Config::default()));
        let fail = Arc::new(AtomicBool::new(false));
        let hal = Watch {
            inner: VirtualHal::default().with_dhcp6_server(server.clone()),
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

    fn run(&mut self, ms: u64) {
        let end = self.now + ms;
        while self.now <= end {
            self.s.dhcp_service(self.now);
            self.now += 250;
        }
    }

    fn client(&mut self, id: &str) -> Value {
        let rows = self.ok("ipv6.dhcp-client.list", Value::Null);
        rows.as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .cloned()
            .unwrap_or_else(|| panic!("{id} not listed: {rows}"))
    }

    fn add(&mut self, p: Value) -> String {
        self.ok("ipv6.dhcp-client.add", p)["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn wan(&mut self) -> String {
        let id = self
            .add(json!({"interface": "ether1", "request": "address,prefix", "pool_name": "pd"}));
        self.run(2_000);
        id
    }

    fn addresses(&mut self) -> Vec<Value> {
        self.ok("ip.address.list", Value::Null)
            .as_array()
            .unwrap()
            .clone()
    }

    fn routes(&mut self) -> Vec<Value> {
        self.ok("ip.route.list", Value::Null)
            .as_array()
            .unwrap()
            .clone()
    }

    fn data_plane(&self) -> Vec<String> {
        let c = self.applied.lock().unwrap();
        c.ip.addresses
            .iter()
            .map(|a| format!("{}@{}", a.address, a.interface))
            .chain(
                c.ip.routes
                    .iter()
                    .map(|r| format!("{} via {}", r.dst_address, r.gateway)),
            )
            .collect()
    }

    fn events(&mut self) -> Vec<String> {
        self.ok("ipv6.dhcp-client.history", Value::Null)["events"]
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

/// The address the lab gives a client with DUID-LL `duid` (`0x00030001` + MAC).
fn mine(duid: &Value) -> String {
    let hex = duid.as_str().unwrap().trim_start_matches("0x00030001");
    let mac: Vec<u8> = (0..6)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    LabServer6::address_for(&"ether1".parse().unwrap(), mac.try_into().unwrap()).to_string()
}

#[test]
fn a_wan_client_gets_an_address_and_a_prefix() {
    let mut l = Lab::new(Knobs::default());
    let id = l.add(json!({"interface": "ether1", "request": "address,prefix", "pool_name": "pd", "comment": "WAN"}));
    assert_eq!(
        l.client(&id)["status"],
        "stopped",
        "nothing runs before the service"
    );
    l.run(2_000);
    let c = l.client(&id);
    assert_eq!(c["status"], "bound", "{c}");
    let mine = || mine(&c["duid"]);
    assert_eq!(c["address"], format!("{}/128", mine()));
    assert_eq!(c["prefix"], "2001:db8:1:100::/56");
    assert_eq!(c["dhcp_server"], "fe80::dc:ff:fe00:1");
    assert_eq!(c["primary_dns"], "2001:db8:0:1::1");
    assert_eq!(c["domains"], json!(["lab.test"]));
    assert_eq!(c["t1_after"], "14m59s");
    assert!(
        c["duid"].as_str().unwrap().starts_with("0x00030001"),
        "DUID-LL"
    );
    assert_eq!(c["flags"], "");

    // The address: dynamic /128 on the interface, in the data plane.
    let a = l.addresses();
    let dhcp = a.iter().find(|a| a["origin"] == "dhcpv6").unwrap();
    assert_eq!(dhcp["flags"], "D");
    assert_eq!(dhcp["address"], format!("{}/128", mine()));
    assert!(l.data_plane().contains(&format!("{}/128@ether1", mine())));
    // The prefix: a pool.
    let pools = l.ok("ipv6.pool.list", Value::Null);
    assert_eq!(pools[0]["name"], "pd");
    assert_eq!(pools[0]["prefix"], "2001:db8:1:100::/56");
    assert_eq!(pools[0]["flags"], "D");
    assert_eq!(pools[0]["valid_lifetime"], "1h");
    // Options as received.
    let opts = l.ok("ipv6.dhcp-client.options", json!({"id": id}));
    let opts = opts["options"].as_array().unwrap();
    assert!(
        opts.iter().any(|o| o["name"] == "ia-pd"
            && o["value"].as_str().unwrap().contains("2001:db8:1:100::/56"))
    );
    assert!(
        opts.iter()
            .any(|o| o["name"] == "dns-servers" && o["value"] == "2001:db8:0:1::1")
    );
    assert_eq!(
        l.s.dhcp6_peer_dns(),
        vec!["2001:db8:0:1::1".parse::<std::net::Ipv6Addr>().unwrap()]
    );
    assert!(
        l.events()
            .iter()
            .any(|e| e.starts_with("bound: got address"))
    );
    assert!(
        l.s.store().running().ip.addresses.is_empty(),
        "nothing of the lease in the config"
    );
}

#[test]
fn lan_addresses_come_from_the_pool_and_follow_it() {
    let mut l = Lab::new(Knobs::default());
    let id = l.add(json!({"interface": "ether1", "request": "prefix", "pool_name": "pd"}));
    let lan = l.ok(
        "ip.address.add",
        json!({"address": "::1/64", "interface": "ether2", "from_pool": "pd"}),
    )["id"]
        .as_str()
        .unwrap()
        .to_owned();
    l.ok(
        "ip.address.add",
        json!({"address": "0:0:0:1::1/64", "interface": "ether3", "from_pool": "pd"}),
    );
    // No prefix yet: listed invalid with the reason, not installed.
    let row = l.addresses().into_iter().find(|a| a["id"] == lan).unwrap();
    assert_eq!(row["flags"], "I");
    assert!(
        row["reason"].as_str().unwrap().contains("no prefix yet"),
        "{row}"
    );
    assert!(!l.data_plane().iter().any(|a| a.ends_with("@ether2")));
    l.run(2_000);
    let row = l.addresses().into_iter().find(|a| a["id"] == lan).unwrap();
    assert_eq!(row["address"], "2001:db8:1:100::1/64");
    assert_eq!(row["origin"], "pool");
    assert_eq!(row["flags"], "");
    let dp = l.data_plane();
    assert!(
        dp.contains(&"2001:db8:1:100::1/64@ether2".to_owned()),
        "{dp:?}"
    );
    assert!(
        dp.contains(&"2001:db8:1:101::1/64@ether3".to_owned()),
        "{dp:?}"
    );
    let pools = l.ok("ipv6.pool.list", Value::Null);
    assert_eq!(pools[0]["used"].as_array().unwrap().len(), 2);
    // Connected routes for the LANs.
    assert!(
        l.routes()
            .iter()
            .any(|r| r["dst_address"] == "2001:db8:1:100::/64" && r["flags"] == "ADC")
    );

    // Renumbering: the ISP delegates another prefix; the LANs follow.
    l.server
        .set(|k| k.prefix = Some("2001:db8:9:900::/56".parse().unwrap()));
    l.ok("ipv6.dhcp-client.release", json!({"id": id}));
    l.run(3_000);
    let dp = l.data_plane();
    assert!(
        dp.contains(&"2001:db8:9:900::1/64@ether2".to_owned()),
        "{dp:?}"
    );
    assert!(
        !dp.iter().any(|a| a.starts_with("2001:db8:1:100::1/64")),
        "{dp:?}"
    );

    // Disabling the client: the LAN addresses leave the data plane, stay in the config.
    l.ok("ipv6.dhcp-client.set", json!({"id": id, "disabled": true}));
    l.run(500);
    assert!(!l.data_plane().iter().any(|a| a.ends_with("@ether2")));
    assert_eq!(l.s.store().running().ip.addresses.len(), 2);
    assert!(
        l.events()
            .iter()
            .any(|e| e.starts_with("stopped: client disabled"))
    );
}

#[test]
fn pool_mistakes_are_refused_with_the_reason() {
    let mut l = Lab::new(Knobs::default());
    l.add(json!({"interface": "ether1", "request": "prefix", "pool_name": "pd"}));
    l.fails(
        "ip.address.add",
        json!({"address": "::1/64", "interface": "ether2", "from_pool": "nope"}),
        "no DHCPv6 client delegates a prefix into pool 'nope'",
    );
    l.fails(
        "ip.address.add",
        json!({"address": "10.0.0.1/24", "interface": "ether2", "from_pool": "pd"}),
        "only IPv6",
    );
    l.ok(
        "ip.address.add",
        json!({"address": "::1/64", "interface": "ether2", "from_pool": "pd"}),
    );
    l.fails(
        "ip.address.add",
        json!({"address": "::2/64", "interface": "ether3", "from_pool": "pd"}),
        "is already on 'ether2'",
    );
    // The client that fills a used pool cannot go.
    l.fails(
        "ipv6.dhcp-client.remove",
        json!({"id": "*1"}),
        "takes its prefix from pool 'pd'",
    );
}

#[test]
fn client_validation_changes_nothing() {
    let mut l = Lab::new(Knobs::default());
    l.fails(
        "ipv6.dhcp-client.add",
        json!({"interface": "ether1"}),
        "request",
    );
    l.fails(
        "ipv6.dhcp-client.add",
        json!({"interface": "ether1", "request": "info"}),
        "not supported",
    );
    l.fails(
        "ipv6.dhcp-client.add",
        json!({"interface": "ether1", "request": "prefix"}),
        "pool_name",
    );
    l.fails(
        "ipv6.dhcp-client.add",
        json!({"interface": "ether9", "request": "address"}),
        "does not exist",
    );
    l.fails(
        "ipv6.dhcp-client.add",
        json!({"interface": "ether1", "request": "prefix", "pool_name": "pd", "prefix_hint": "::/96"}),
        "cannot number a LAN",
    );
    l.fails(
        "ipv6.dhcp-client.add",
        json!({"interface": "ether1", "request": "address", "custom_duid": "zz"}),
        "custom_duid",
    );
    l.fails(
        "ipv6.dhcp-client.add",
        json!({"interface": "ether1", "request": "address", "allowed_servers": "nonsense"}),
        "allowed server",
    );
    l.fails(
        "ipv6.dhcp-client.add",
        json!({"interface": "ether1", "request": "address", "default_route_distance": 0}),
        "1..=255",
    );
    l.add(json!({"interface": "ether1", "request": "prefix", "pool_name": "pd", "prefix_hint": "::/0"}));
    assert_eq!(l.client("*1")["prefix_hint"], "", "::/0 = no hint");
    l.fails(
        "ipv6.dhcp-client.add",
        json!({"interface": "ether1", "request": "address"}),
        "one per interface",
    );
    l.fails(
        "ipv6.dhcp-client.add",
        json!({"interface": "ether2", "request": "prefix", "pool_name": "pd"}),
        "already filled",
    );
    l.fails(
        "ipv6.dhcp-client.set",
        json!({"id": "*9", "disabled": true}),
        "no DHCPv6 client *9",
    );
    // A data-plane refusal rolls the command back.
    l.fail.store(true, Ordering::Relaxed);
    l.fails(
        "ipv6.dhcp-client.add",
        json!({"interface": "ether2", "request": "address"}),
        "test: apply fails",
    );
}

#[test]
fn router_advertisements_follow_the_policy() {
    let mut l = Lab::new(Knobs::default());
    let ra_addrs = |l: &mut Lab| -> Vec<String> {
        l.addresses()
            .into_iter()
            .filter(|a| a["origin"] == "ra")
            .map(|a| {
                format!(
                    "{}@{}",
                    a["address"].as_str().unwrap(),
                    a["interface"].as_str().unwrap()
                )
            })
            .collect()
    };
    // Safe default (auto): no DHCPv6 client, no RA anywhere.
    assert!(ra_addrs(&mut l).is_empty());
    let st = l.ok("ipv6.settings.get", Value::Null);
    assert_eq!(st["accept_router_advertisements"], "auto");
    assert_eq!(st["interfaces"][0]["accepts"], false);
    // A WAN client: RA accepted there only (SLAAC address, default route).
    l.wan();
    let ra = ra_addrs(&mut l);
    assert_eq!(ra.len(), 1, "{ra:?}");
    assert!(
        ra[0].starts_with("2001:db8:0:1:") && ra[0].ends_with("/64@ether1"),
        "{ra:?}"
    );
    let routes = l.routes();
    let default = routes.iter().find(|r| r["dst_address"] == "::/0").unwrap();
    assert_eq!(default["gateway"], "fe80::dc:ff:fe00:1%ether1");
    assert_eq!(default["origin"], "ra");
    assert_eq!(default["flags"], "AD");
    let st = l.ok("ipv6.settings.get", Value::Null);
    let e1 = st["interfaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["interface"] == "ether1")
        .unwrap()
        .clone();
    assert_eq!(e1["accept"], "on");
    assert!(e1["why"].as_str().unwrap().contains("DHCPv6 client"));
    // RA-learned entries cannot be removed by hand.
    l.ok(
        "ip.address.add",
        json!({"address": "10.9.9.1/24", "interface": "ether8"}),
    );
    let id = l
        .addresses()
        .into_iter()
        .find(|a| a["origin"] == "ra")
        .unwrap()["id"]
        .clone();
    l.fails(
        "ip.address.remove",
        json!({"id": id}),
        "Router Advertisement",
    );
    // no: nowhere. yes: everywhere in the list.
    l.ok(
        "ipv6.settings.set",
        json!({"accept_router_advertisements": "no"}),
    );
    assert!(ra_addrs(&mut l).is_empty());
    l.ok(
        "ipv6.settings.set",
        json!({"accept_router_advertisements": "yes"}),
    );
    assert_eq!(ra_addrs(&mut l).len(), 8, "every lab port");
    l.ok(
        "interface.list.member.add",
        json!({"list": "WAN", "interface": "ether2"}),
    );
    l.ok(
        "ipv6.settings.set",
        json!({"accept_router_advertisements_on": "WAN"}),
    );
    let ra = ra_addrs(&mut l);
    assert_eq!(ra.len(), 1);
    assert!(ra[0].ends_with("@ether2"));
    l.fails(
        "interface.list.remove",
        json!({"name": "WAN"}),
        "accept RA on 'WAN'",
    );
    l.fails(
        "ipv6.settings.set",
        json!({"accept_router_advertisements_on": "NOPE"}),
        "no interface list",
    );
    l.fails(
        "ipv6.settings.set",
        json!({"accept_router_advertisements": "maybe"}),
        "expected auto",
    );
    // The lab forwards: yes-if-forwarding-disabled takes none.
    l.ok(
        "ipv6.settings.set",
        json!({"accept_router_advertisements": "yes-if-forwarding-disabled"}),
    );
    assert!(ra_addrs(&mut l).is_empty());
}

#[test]
fn a_default_route_via_the_server_when_asked() {
    let mut l = Lab::new(Knobs::default());
    let id = l.wan();
    assert!(
        !l.data_plane().iter().any(|r| r.starts_with("::/0")),
        "off by default"
    );
    l.ok(
        "ipv6.dhcp-client.set",
        json!({"id": id, "add_default_route": true, "default_route_distance": 5}),
    );
    l.run(500);
    let r = l
        .routes()
        .into_iter()
        .find(|r| r["dst_address"] == "::/0" && r["origin"] == "dhcp")
        .unwrap();
    assert_eq!(r["gateway"], "fe80::dc:ff:fe00:1%ether1");
    assert_eq!(r["distance"], 5);
    assert_eq!(r["flags"], "ADS", "it beats the RA route (metric 1024)");
    assert!(
        l.data_plane()
            .contains(&"::/0 via fe80::dc:ff:fe00:1%ether1".to_owned())
    );
    l.ok(
        "ip.route.add",
        json!({"dst_address": "2001:db8:99::/48", "gateway": "fe80::1%ether1"}),
    );
    l.fails(
        "ip.route.remove",
        json!({"id": r["id"]}),
        "ipv6.dhcp-client.set",
    );
}

#[test]
fn renew_release_and_a_server_that_forgot_us() {
    let mut l = Lab::new(Knobs::default());
    let id = l.wan();
    let r = l.ok("ipv6.dhcp-client.renew", json!({"id": id}));
    assert_eq!(r["status"], "bound");
    assert!(l.events().iter().any(|e| e.starts_with("renewed:")));
    // NoBinding on renew → Request → bound again.
    l.server.set(|k| k.no_binding = true);
    l.ok("ipv6.dhcp-client.renew", json!({"id": id}));
    l.server.set(|k| k.no_binding = false);
    l.run(3_000);
    assert_eq!(l.client(&id)["status"], "bound");
    assert!(l.events().iter().any(|e| e.contains("NoBinding")));
    // Release: the address leaves the data plane at once.
    l.server.set(|k| k.silent = true);
    let r = l.ok("ipv6.dhcp-client.release", json!({"id": id}));
    assert_eq!(r["status"], "searching");
    assert!(!l.data_plane().iter().any(|a| a.contains("/128@")));
    assert!(
        l.events()
            .iter()
            .any(|e| e.starts_with("lost:") && e.contains("released"))
    );
}

#[test]
fn a_prefix_without_an_address_and_refused_servers() {
    let mut l = Lab::new(Knobs {
        no_address: true,
        ..Knobs::default()
    });
    let id = l.wan();
    let c = l.client(&id);
    assert_eq!(c["status"], "bound");
    assert_eq!(c["address"], Value::Null);
    assert_eq!(c["prefix"], "2001:db8:1:100::/56");
    assert!(
        c["missing"][0].as_str().unwrap().contains("NoAddrsAvail"),
        "{c}"
    );
    // accept-prefix-without-address=no: that server is not good enough.
    l.ok(
        "ipv6.dhcp-client.set",
        json!({"id": id, "accept_prefix_without_address": false}),
    );
    l.ok("ipv6.dhcp-client.renew", json!({"id": id}));
    l.run(5_000);
    assert_ne!(l.client(&id)["status"], "bound");

    let mut l = Lab::new(Knobs::default());
    let id = l.add(json!({"interface": "ether1", "request": "address", "allowed_servers": "fe80::99, 0x00030001aabbccddeeff"}));
    l.run(5_000);
    assert_eq!(l.client(&id)["status"], "searching");
    assert!(l.events().iter().any(|e| e.starts_with("refused:")));
    // By the MAC inside the server's DUID-LL.
    l.ok(
        "ipv6.dhcp-client.set",
        json!({"id": id, "allowed_servers": ["02:DC:00:00:00:01"]}),
    );
    l.ok("ipv6.dhcp-client.renew", json!({"id": id}));
    l.run(3_000);
    assert_eq!(l.client(&id)["status"], "bound");
}

#[test]
fn renew_without_a_service_clock_says_why() {
    let mut l = Lab::new(Knobs::default());
    let id = l.add(json!({"interface": "ether1", "request": "address"}));
    let e =
        l.s.execute("ipv6.dhcp-client.renew", &json!({"id": id}))
            .unwrap_err();
    assert!(e.to_string().contains("no service clock"), "{e}");
}

#[test]
fn the_config_round_trips_and_transactions_work() {
    let mut l = Lab::new(Knobs::default());
    l.ok("config.mode.set", json!({"mode": "transactional"}));
    l.add(json!({"interface": "ether1", "request": "prefix", "pool_name": "pd", "prefix_hint": "::/60"}));
    l.ok(
        "ip.address.add",
        json!({"address": "::1/64", "interface": "ether2", "from_pool": "pd"}),
    );
    l.run(1_000);
    assert!(
        l.ok("ipv6.pool.list", Value::Null)
            .as_array()
            .unwrap()
            .is_empty()
            || l.ok("ipv6.pool.list", Value::Null)[0]["prefix"].is_null()
    );
    l.ok("config.commit", json!({}));
    l.run(2_000);
    assert_eq!(
        l.ok("ipv6.pool.list", Value::Null)[0]["prefix"],
        "2001:db8:1:100::/60"
    );
    assert!(
        l.data_plane()
            .contains(&"2001:db8:1:100::1/64@ether2".to_owned())
    );
    let text = corerouter_model::persist::encode(l.s.store()).unwrap();
    assert!(
        text.contains("\"from_pool\": \"pd\"") || text.contains("\"from_pool\":\"pd\""),
        "{text}"
    );
}

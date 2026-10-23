//! G1.27a — IP › Routes read and diagnosed: state and origin of every
//! route, the gateway split into its parts, why a route is standby or
//! inactive (each case), ECMP groups, the Changed column, the list filters
//! and `ip.route.lookup` (overlapping prefixes, VRF, ECMP, the table rule,
//! local and unreachable answers, and the data plane's answer next to it).
// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use corerouter_engine::Session;
use corerouter_engine::route_table::REASONS;
use corerouter_hal::drift::{KernelRoute, Snapshot};
use corerouter_hal::route_get::{KernelLookup, RouteQuery};
use corerouter_hal::virt::LabKernel;
use corerouter_hal::{Hal, HalError, LinkInfo, LinkState, VirtualHal};
use corerouter_model::{Config, IfName};
use serde_json::{Value, json};

/// The virtual lab, with links that can lose their carrier.
struct Lab {
    inner: VirtualHal,
    unplugged: Arc<Mutex<BTreeSet<String>>>,
}

impl Hal for Lab {
    fn describe(&self) -> String {
        self.inner.describe()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.inner.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        self.inner.apply(from, to)
    }
    fn poll(&mut self) -> Vec<LinkState> {
        let off = self.unplugged.lock().unwrap().clone();
        let mut live = self.inner.poll();
        for l in &mut live {
            if off.contains(l.name.as_str()) {
                l.running = false;
            }
        }
        live
    }
    fn now_unix(&self) -> Option<u64> {
        None
    }
    fn route_get(&mut self, cfg: &Config, q: &RouteQuery) -> Result<KernelLookup, HalError> {
        self.inner.route_get(cfg, q)
    }
    fn snapshot(&mut self, cfg: &Config) -> Result<Snapshot, HalError> {
        self.inner.snapshot(cfg)
    }
}

struct T {
    s: Session,
    kernel: LabKernel,
    unplugged: Arc<Mutex<BTreeSet<String>>>,
    clock: u64,
}

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

/// ether1 = 10.0.0.2/24 + 2001:db8::2/64 (uplink), ether2 = 10.0.1.2/24,
/// ether3 = 192.168.88.1/24; VRF `blue` with ether4 = 10.0.0.2/24 too.
fn lab() -> T {
    let inner = VirtualHal::new(8);
    let kernel = inner.kernel();
    let unplugged = Arc::new(Mutex::new(BTreeSet::new()));
    let mut s = Session::new(Box::new(Lab {
        inner,
        unplugged: Arc::clone(&unplugged),
    }));
    ok(
        &mut s,
        "ip.vrf.add",
        json!({"name": "blue", "interfaces": "ether4"}),
    );
    for (a, i) in [
        ("10.0.0.2/24", "ether1"),
        ("2001:db8::2/64", "ether1"),
        ("10.0.1.2/24", "ether2"),
        ("192.168.88.1/24", "ether3"),
        ("10.0.0.2/24", "ether4"),
    ] {
        ok(
            &mut s,
            "ip.address.add",
            json!({"address": a, "interface": i}),
        );
    }
    let mut t = T {
        s,
        kernel,
        unplugged,
        clock: 1_000,
    };
    t.tick(0);
    t
}

impl T {
    fn add(&mut self, p: Value) -> String {
        ok(&mut self.s, "ip.route.add", p)["id"]
            .as_str()
            .unwrap()
            .to_owned()
    }

    fn list(&mut self, p: Value) -> Vec<Value> {
        let rows = ok(&mut self.s, "ip.route.list", p)
            .as_array()
            .unwrap()
            .clone();
        rows.iter().for_each(listed_reason);
        rows
    }

    fn row(&mut self, id: &str) -> Value {
        self.list(json!({}))
            .into_iter()
            .find(|r| r["id"] == id)
            .unwrap_or_else(|| panic!("{id} not listed"))
    }

    fn lookup(&mut self, p: Value) -> Value {
        ok(&mut self.s, "ip.route.lookup", p)
    }

    fn tick(&mut self, secs: u64) {
        self.clock += secs;
        self.s.tick(self.clock);
    }

    fn unplug(&mut self, name: &str, off: bool) {
        let mut u = self.unplugged.lock().unwrap();
        if off {
            u.insert(name.into());
        } else {
            u.remove(name);
        }
    }
}

/// A row's reason is one of `REASONS`, with exactly its places as args
/// (what the GUI's translation fills in).
fn listed_reason(r: &Value) {
    let Some(id) = r["reason_id"].as_str() else {
        assert_eq!(r["reason"], Value::Null, "{r}");
        return;
    };
    let (_, en) = REASONS
        .iter()
        .find(|(i, _)| *i == id)
        .unwrap_or_else(|| panic!("reason {id} not in REASONS"));
    let mut places: Vec<&str> = en
        .split('{')
        .skip(1)
        .filter_map(|p| p.split_once('}').map(|(n, _)| n))
        .collect();
    places.sort_unstable();
    places.dedup();
    let mut args: Vec<&str> = r["reason_args"]
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    args.sort_unstable();
    assert_eq!(args, places, "{id}: {r}");
}

// ---- ip.route.list ----

#[test]
fn every_row_says_state_origin_and_the_gateway_in_parts() {
    let mut t = lab();
    let id = t.add(json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}));
    let r = t.row(&id);
    assert_eq!(r["state"], "active");
    assert_eq!(r["origin"], "static");
    assert_eq!(r["family"], "ipv4");
    assert_eq!(r["gateway_address"], "10.0.0.1");
    assert_eq!(r["gateway_interface"], Value::Null);
    assert_eq!(r["gateway_status"], "reachable");
    assert_eq!(r["interface"], "ether1");
    assert_eq!(r["immediate_gw"], "10.0.0.1%ether1");
    assert_eq!(r["check_gateway"], Value::Null);
    assert_eq!(r["flags"], "AS", "the terminal keeps RouterOS' letters");
    assert_eq!(r["key"], id);
    let conn = t
        .list(json!({"origin": "connected"}))
        .into_iter()
        .find(|r| r["dst_address"] == "10.0.1.0/24")
        .unwrap();
    assert_eq!(conn["state"], "active");
    assert_eq!(conn["gateway_status"], Value::Null);
    assert_eq!(conn["gateway_interface"], "ether2");
    assert_eq!(conn["key"], "connected main 10.0.1.0/24 ether2");
}

#[test]
fn each_inactive_or_standby_route_says_why() {
    let mut t = lab();
    let primary = t.add(json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}));
    let backup = t.add(json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.1.1", "distance": 5}));
    let off =
        t.add(json!({"dst_address": "198.51.100.0/24", "gateway": "10.0.1.1", "disabled": true}));
    let via_disabled = t.add(json!({"dst_address": "203.0.113.0/24", "gateway": "ether3"}));
    let unplugged = t.add(json!({"dst_address": "192.0.2.0/24", "gateway": "10.0.1.1"}));
    let r = t.row(&backup);
    assert_eq!(
        (&r["state"], &r["reason_id"]),
        (&json!("standby"), &json!("loses-distance"))
    );
    assert_eq!(
        r["reason"],
        format!("loses to distance 1 (route {primary} via 10.0.0.1%ether1)")
    );
    assert_eq!(t.row(&off)["reason_id"], "disabled");

    ok(
        &mut t.s,
        "interface.set",
        json!({"name": "ether3", "disabled": true}),
    );
    let r = t.row(&via_disabled);
    assert_eq!(
        (&r["state"], &r["reason_id"]),
        (&json!("inactive"), &json!("interface-disabled"))
    );
    assert_eq!(r["gateway_status"], "unreachable");
    assert_eq!(r["reason_args"]["interface"], "ether3");

    // Carrier lost on ether2: its routes (and its connected network) go.
    t.unplug("ether2", true);
    t.tick(1);
    let r = t.row(&unplugged);
    assert_eq!(
        (&r["state"], &r["reason_id"]),
        (&json!("inactive"), &json!("interface-down"))
    );
    assert_eq!(r["reason"], "interface 'ether2' has no link");
    let conn = t
        .list(json!({"origin": "connected"}))
        .into_iter()
        .find(|r| r["dst_address"] == "10.0.1.0/24")
        .unwrap();
    assert_eq!(conn["reason_id"], "interface-down");
    t.unplug("ether2", false);
    t.tick(1);
    assert_eq!(t.row(&unplugged)["state"], "active");

    // A static route to a connected network stays behind it.
    let shadow = t.add(json!({"dst_address": "10.0.1.0/24", "gateway": "ether3"}));
    ok(
        &mut t.s,
        "interface.set",
        json!({"name": "ether3", "disabled": false}),
    );
    t.tick(1);
    let r = t.row(&shadow);
    assert_eq!(
        (&r["state"], &r["reason_id"]),
        (&json!("standby"), &json!("connected-wins"))
    );
}

#[test]
fn the_address_behind_a_gateway_disabled_makes_it_inactive() {
    let mut t = lab();
    ok(
        &mut t.s,
        "ip.address.add",
        json!({"address": "10.0.5.2/24", "interface": "ether2", "disabled": true}),
    );
    let id = t.add(json!({"dst_address": "192.0.2.0/24", "gateway": "10.0.5.1%ether2"}));
    let r = t.row(&id);
    assert_eq!(
        (&r["state"], &r["reason_id"]),
        (&json!("inactive"), &json!("address-disabled"))
    );
}

#[test]
fn equal_distances_form_an_ecmp_group_until_one_path_fails() {
    let mut t = lab();
    let a = t.add(json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}));
    let b = t.add(json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.1.1"}));
    for id in [&a, &b] {
        let r = t.row(id);
        assert_eq!(
            (&r["state"], &r["ecmp"], &r["flags"]),
            (&json!("active"), &json!(2), &json!("AS+"))
        );
    }
    // Both paths are in the lab kernel, as one group.
    let k = t.kernel.lock().unwrap().routes.clone();
    assert_eq!(k.iter().filter(|r| r.dst.prefix_len() == 0).count(), 2);
    t.unplug("ether2", true);
    t.tick(1);
    assert_eq!(t.row(&a)["ecmp"], 1);
    assert_eq!(t.row(&b)["reason_id"], "interface-down");
}

#[test]
fn list_filters_and_refuses_unknown_values() {
    let mut t = lab();
    t.add(json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}));
    t.add(json!({"dst_address": "::/0", "gateway": "2001:db8::1"}));
    t.add(json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.1.1", "distance": 9}));
    t.add(json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1", "routing_table": "blue"}));
    let v6 = t.list(json!({"family": "ipv6"}));
    assert!(v6.iter().all(|r| r["family"] == "ipv6") && !v6.is_empty());
    assert_eq!(t.list(json!({"state": "standby"})).len(), 1);
    assert!(
        t.list(json!({"origin": "static", "routing_table": "blue"}))
            .len()
            == 1
    );
    assert!(
        t.list(json!({"state": "active"}))
            .iter()
            .all(|r| r["active"] == true)
    );
    let err =
        t.s.execute("ip.route.list", &json!({"state": "maybe"}))
            .unwrap_err()
            .to_string();
    assert!(
        err.contains("not one of active, standby, inactive"),
        "{err}"
    );
    let err =
        t.s.execute("ip.route.list", &json!({"family": "ipx"}))
            .unwrap_err()
            .to_string();
    assert!(err.contains("ipv4, ipv6"), "{err}");
}

#[test]
fn changed_says_how_long_a_route_has_been_in_its_state() {
    let mut t = lab();
    let id = t.add(json!({"dst_address": "192.0.2.0/24", "gateway": "10.0.1.1"}));
    t.row(&id);
    t.tick(30);
    let r = t.row(&id);
    assert_eq!(r["changed_secs"], 30, "{r}");
    t.unplug("ether2", true);
    t.tick(1);
    t.tick(4);
    let r = t.row(&id);
    assert_eq!(
        (&r["state"], &r["changed_secs"]),
        (&json!("inactive"), &json!(4))
    );
    // Seen before watching began: unknown, not zero.
    let old = t
        .list(json!({"origin": "connected"}))
        .into_iter()
        .find(|r| r["dst_address"] == "10.0.0.0/24")
        .unwrap();
    assert_eq!(old["changed_secs"], Value::Null);
}

#[test]
fn route_changes_roll_back_with_the_list_following() {
    let mut t = lab();
    let id = t.add(json!({"dst_address": "192.0.2.0/24", "gateway": "10.0.1.1"}));
    let rev = t.s.store().current_revision();
    ok(
        &mut t.s,
        "ip.route.set",
        json!({"id": id, "disabled": true}),
    );
    assert_eq!(t.row(&id)["state"], "inactive");
    ok(&mut t.s, "config.rollback", json!({"revision": rev}));
    assert_eq!(t.row(&id)["state"], "active");
}

// ---- ip.route.lookup ----

#[test]
fn lookup_takes_the_longest_prefix_and_says_the_rest() {
    let mut t = lab();
    t.add(json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}));
    let wide = t.add(json!({"dst_address": "192.0.2.0/24", "gateway": "10.0.0.1"}));
    let narrow = t.add(json!({"dst_address": "192.0.2.0/25", "gateway": "10.0.1.1"}));
    let r = t.lookup(json!({"address": "192.0.2.7"}));
    assert_eq!(r["type"], "unicast");
    assert_eq!(r["route"]["id"], narrow);
    assert_eq!(r["prefix"], "192.0.2.0/25");
    assert_eq!(
        (&r["interface"], &r["gateway"]),
        (&json!("ether2"), &json!("10.0.1.1"))
    );
    assert_eq!(r["src"], "10.0.1.2");
    assert_eq!(r["routing_table"], "main");
    assert!(r["rule"].as_str().unwrap().contains("main table"));
    assert_eq!(r["kernel"]["same"], true, "{r}");
    assert_eq!(
        t.lookup(json!({"address": "192.0.2.200"}))["route"]["id"],
        wide
    );
    assert_eq!(
        t.lookup(json!({"address": "8.8.8.8"}))["prefix"],
        "0.0.0.0/0"
    );
    // On a connected network: no gateway.
    let c = t.lookup(json!({"address": "192.168.88.20"}));
    assert_eq!(
        (&c["gateway"], &c["interface"], &c["route"]["origin"]),
        (&Value::Null, &json!("ether3"), &json!("connected"))
    );
    // The router itself.
    let l = t.lookup(json!({"address": "10.0.1.2"}));
    assert_eq!(
        (&l["type"], &l["kernel"]["type"]),
        (&json!("local"), &json!("local"))
    );
    // Nothing for IPv6 beyond the connected /64.
    let u = t.lookup(json!({"address": "2001:db8:ffff::1"}));
    assert_eq!(
        (&u["type"], &u["kernel"]["type"]),
        (&json!("unreachable"), &json!("unreachable"))
    );
    // Disabled: the backup is the route now.
    ok(
        &mut t.s,
        "ip.route.set",
        json!({"id": narrow, "disabled": true}),
    );
    assert_eq!(
        t.lookup(json!({"address": "192.0.2.7"}))["route"]["id"],
        wide
    );
}

#[test]
fn lookup_in_a_vrf_by_table_or_by_source() {
    let mut t = lab();
    t.add(json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}));
    let blue = t
        .add(json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.254", "routing_table": "blue"}));
    let r = t.lookup(json!({"address": "8.8.8.8", "table": "blue"}));
    assert_eq!(
        (&r["route"]["id"], &r["interface"]),
        (&json!(blue), &json!("ether4"))
    );
    assert_eq!(r["routing_table"], "blue");
    // Source on ether1 (main) and the same address on ether4 (blue): the
    // first address holding it decides, here ether1 → main.
    let r = t.lookup(json!({"address": "8.8.8.8", "src": "10.0.1.2"}));
    assert_eq!(r["routing_table"], "main");
    ok(
        &mut t.s,
        "ip.address.add",
        json!({"address": "172.16.0.1/24", "interface": "ether4"}),
    );
    let r = t.lookup(json!({"address": "8.8.8.8", "src": "172.16.0.1"}));
    assert_eq!(r["routing_table"], "blue");
    assert!(r["rule"].as_str().unwrap().contains("VRF 'blue'"), "{r}");
    assert_eq!(r["src"], "172.16.0.1");
}

#[test]
fn lookup_gives_every_path_of_an_ecmp_group() {
    let mut t = lab();
    t.add(json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}));
    t.add(json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.1.1"}));
    let r = t.lookup(json!({"address": "8.8.8.8"}));
    assert_eq!(r["ecmp"], true);
    assert_eq!(r["nexthops"].as_array().unwrap().len(), 2, "{r}");
    assert_eq!(r["kernel"]["nexthops"].as_array().unwrap().len(), 2);
    assert_eq!(r["kernel"]["same"], true);
}

#[test]
fn lookup_shows_where_the_kernel_differs() {
    let mut t = lab();
    t.add(json!({"dst_address": "192.0.2.0/24", "gateway": "10.0.0.1"}));
    // Someone added a more specific route behind CoreRouter's back.
    t.kernel.lock().unwrap().routes.insert(KernelRoute {
        table: 254,
        dst: "192.0.2.0/26".parse().unwrap(),
        metric: 1,
        link: "ether2".parse::<IfName>().unwrap(),
        gateway: Some("10.0.1.9".parse().unwrap()),
    });
    let r = t.lookup(json!({"address": "192.0.2.1"}));
    assert_eq!(r["kernel"]["same"], false);
    let diff = r["kernel"]["differences"].to_string();
    assert!(
        diff.contains("192.0.2.0/26") && diff.contains("10.0.1.9%ether2"),
        "{diff}"
    );
}

#[test]
fn lookup_refuses_bad_requests() {
    let mut t = lab();
    for (p, needle) in [
        (json!({"address": "nope"}), "address"),
        (
            json!({"address": "8.8.8.8", "table": "red"}),
            "routing table 'red' does not exist",
        ),
        (
            json!({"address": "8.8.8.8", "src": "203.0.113.9"}),
            "not an address of this router",
        ),
        (
            json!({"address": "8.8.8.8", "src": "2001:db8::2"}),
            "same family",
        ),
        (
            json!({"address": "8.8.8.8", "via": "x"}),
            "unknown parameter 'via'",
        ),
        (json!({}), "'address': is required"),
    ] {
        let err = t.s.execute("ip.route.lookup", &p).unwrap_err().to_string();
        assert!(err.contains(needle), "{p}: '{err}' lacks '{needle}'");
    }
}

// ---- ip.route.detail (G1.27b) ----

impl T {
    fn detail(&mut self, key: &str) -> Value {
        ok(&mut self.s, "ip.route.detail", json!({ "key": key }))
    }
}

#[test]
fn detail_says_where_a_static_route_came_from() {
    let mut t = lab();
    let id = t.add(json!({"dst_address": "192.0.2.0/24", "gateway": "10.0.1.1"}));
    let d = t.detail(&id);
    assert_eq!(d["source"]["kind"], "static");
    assert_eq!(d["source"]["created"]["command"], "ip.route.add");
    let created = d["source"]["created"]["revision"].clone();
    ok(
        &mut t.s,
        "ip.route.set",
        json!({"id": id, "comment": "transit"}),
    );
    let d = t.detail(&id);
    assert_eq!(d["source"]["created"]["revision"], created);
    assert_eq!(d["source"]["changed"]["command"], "ip.route.set");
    assert_eq!(d["route"]["comment"], "transit");
    // A connected route names its address.
    let d = t.detail("connected main 10.0.1.0/24 ether2");
    assert_eq!(d["source"]["kind"], "connected");
    assert_eq!(d["source"]["text"], "address 10.0.1.2/24 on ether2");
    assert_eq!(d["source"]["created"]["command"], "ip.address.add");
}

#[test]
fn detail_compares_with_the_competitors() {
    let mut t = lab();
    let primary = t.add(json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}));
    let backup = t.add(json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.1.1", "distance": 5}));
    let d = t.detail(&primary);
    assert!(
        d["chosen"]
            .as_str()
            .unwrap()
            .contains("lowest distance (1)"),
        "{d}"
    );
    assert!(
        d["chosen"].as_str().unwrap().contains("(5) takes over"),
        "{d}"
    );
    assert_eq!(d["chosen_id"], "choice.lowest");
    assert_eq!(d["chosen_args"]["next"], "5");
    let comp = d["competitors"].as_array().unwrap();
    assert_eq!(comp.len(), 2);
    assert_eq!(
        (&comp[0]["this"], &comp[1]["state"]),
        (&json!(true), &json!("standby"))
    );
    let d = t.detail(&backup);
    assert!(
        d["chosen"]
            .as_str()
            .unwrap()
            .starts_with("loses to distance 1"),
        "{d}"
    );
    assert_eq!(d["chosen_id"], "route.loses-distance");
    assert_eq!(
        d["check_gateway"],
        Value::Null,
        "static routes have none yet"
    );
}

#[test]
fn detail_keeps_the_failovers_of_the_last_day() {
    let mut t = lab();
    let primary = t.add(json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.1.1"}));
    let backup = t.add(json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1", "distance": 5}));
    t.tick(1);
    t.unplug("ether2", true);
    t.tick(10);
    t.unplug("ether2", false);
    t.tick(20);
    let d = t.detail(&primary);
    let h = d["history"].as_array().unwrap();
    assert_eq!(h.len(), 2, "{d}");
    assert_eq!(
        (&h[0]["from"], &h[0]["to"], &h[0]["ago_secs"]),
        (&json!("inactive"), &json!("active"), &json!(0))
    );
    assert_eq!(
        (&h[1]["to"], &h[1]["ago_secs"]),
        (&json!("inactive"), &json!(20))
    );
    assert_eq!(h[1]["reason"], "interface 'ether2' has no link");
    assert_eq!(h[1]["reason_id"], "interface-down");
    let b = t.detail(&backup);
    let bh = b["history"].as_array().unwrap();
    assert_eq!(
        (&bh[1]["from"], &bh[1]["to"]),
        (&json!("standby"), &json!("active")),
        "{b}"
    );
    // The log has the failover (topic route).
    let log = ok(&mut t.s, "log.print", json!({"topics": "route"})).to_string();
    assert!(
        log.contains("0.0.0.0/0: active -> inactive: interface 'ether2' has no link"),
        "{log}"
    );
    // A day later the changes are gone.
    t.tick(86_401);
    assert_eq!(t.detail(&primary)["history"], json!([]));
}

#[test]
fn detail_says_whether_the_kernel_holds_it() {
    let mut t = lab();
    let id = t.add(json!({"dst_address": "192.0.2.0/24", "gateway": "10.0.1.1"}));
    let d = t.detail(&id);
    assert_eq!(d["kernel"]["same"], true, "{d}");
    assert_eq!(d["kernel"]["expected"].as_array().unwrap().len(), 1);
    // Someone deletes it, and adds another path by hand.
    {
        let mut k = t.kernel.lock().unwrap();
        k.routes.retain(|r| r.dst.to_string() != "192.0.2.0/24");
        k.routes.insert(KernelRoute {
            table: 254,
            dst: "192.0.2.0/24".parse().unwrap(),
            metric: 1,
            link: "ether1".parse::<IfName>().unwrap(),
            gateway: Some("10.0.0.77".parse().unwrap()),
        });
    }
    let d = t.detail(&id);
    assert_eq!(d["kernel"]["same"], false);
    assert!(
        d["kernel"]["missing"][0]
            .as_str()
            .unwrap()
            .contains("via 10.0.1.1"),
        "{d}"
    );
    assert!(
        d["kernel"]["extra"][0]
            .as_str()
            .unwrap()
            .contains("via 10.0.0.77"),
        "{d}"
    );
    let c = t.detail("connected main 10.0.1.0/24 ether2");
    assert_eq!(c["kernel"]["same"], Value::Null);
}

#[test]
fn detail_refuses_unknown_keys() {
    let mut t = lab();
    for (p, needle) in [
        (json!({"key": "*99"}), "no route '*99'"),
        (json!({"key": "x".repeat(300)}), "at most 256 bytes"),
        (json!({}), "'key': is required"),
    ] {
        let err = t.s.execute("ip.route.detail", &p).unwrap_err().to_string();
        assert!(err.contains(needle), "{p}: {err}");
    }
}

//! G1.27d — `/ip arp` and `/ipv6 neighbor` on the virtual lab: the list
//! (search, filters, counts, pages), static entries with journal and
//! rollback, make-static, the flush that keeps the gateway and the
//! management neighbor, the ARP mode with its confirmation and lockout
//! check, ARP ping as a task, and the `incomplete` gateway of IP › Routes.
//!
//! The lab (`hal::lab_neigh`): every subnet of the router has hosts 1–12
//! and 254 that answer; any other gateway stays `incomplete`.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use std::thread;
use std::time::{Duration, Instant};

use corerouter_engine::{Caller, Clock, Job, Link, Principal, Runner, Session};
use serde_json::{Value, json};

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

/// ether1 10.0.0.1/24 with a default route via 10.0.0.254 (a lab host)
/// and 192.0.2.0/24 via 10.0.0.77 (nobody there).
fn lab() -> Session {
    let mut s = Session::virtual_lab();
    run(
        &mut s,
        "ip.address.add",
        json!({"address": "10.0.0.1/24", "interface": "ether1"}),
    );
    run(
        &mut s,
        "ip.address.add",
        json!({"address": "2001:db8:1::1/64", "interface": "ether1"}),
    );
    run(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.254"}),
    );
    run(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "192.0.2.0/24", "gateway": "10.0.0.77"}),
    );
    s
}

fn list(s: &mut Session, p: Value) -> Value {
    run(s, "ip.arp.list", p)
}

fn addrs(v: &Value) -> Vec<String> {
    v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["address"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn the_list_shows_states_counts_and_pages() {
    let mut s = lab();
    let all = list(&mut s, json!({}));
    // 12 lab hosts (1–12 and 254, the router's .1 aside) + the
    // unanswered gateway.
    assert_eq!(all["total"], 13, "{all}");
    assert_eq!(all["counts"]["interfaces"]["ether1"], 13);
    assert_eq!(all["counts"]["states"]["incomplete"], 1);
    assert_eq!(all["counts"]["sources"]["dynamic"], 13);
    assert_eq!(all["table"]["ipv4"], 13);
    assert_eq!(all["table"]["gc_thresh3"], 1024);
    assert_eq!(all["table"]["near_full"], false);
    // Sorted by address.
    let a = addrs(&all);
    assert_eq!(a.first().map(String::as_str), Some("10.0.0.2"));
    assert_eq!(a.last().map(String::as_str), Some("10.0.0.254"));
    let gw = all["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["address"] == "10.0.0.77")
        .unwrap();
    assert_eq!(
        (&gw["state"], &gw["mac_address"]),
        (&json!("incomplete"), &Value::Null)
    );
    assert_eq!(gw["flags"], "D");

    // Pages: the same order cut in pieces.
    let p1 = list(&mut s, json!({"limit": 5}));
    let p2 = list(&mut s, json!({"limit": 5, "offset": 5}));
    assert_eq!([addrs(&p1), addrs(&p2)].concat(), a[..10].to_vec());
    assert_eq!(p2["matched"], 13);

    // Search: address, CIDR, MAC prefix, text; filters by state.
    assert_eq!(
        addrs(&list(&mut s, json!({"search": "10.0.0.3"}))),
        ["10.0.0.3"]
    );
    assert_eq!(list(&mut s, json!({"search": "10.0.0.0/29"}))["matched"], 6);
    let vm = list(&mut s, json!({"search": "00:50:56"}));
    assert!(
        vm["rows"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["mac_address"].as_str().unwrap().starts_with("00:50:56"))
    );
    assert!(vm["matched"].as_u64().unwrap() > 0);
    assert_eq!(
        addrs(&list(&mut s, json!({"state": "incomplete,failed"}))),
        ["10.0.0.77"]
    );
    assert_eq!(list(&mut s, json!({"search": "ether9"}))["matched"], 0);

    // IPv6 is its own list.
    let v6 = run(&mut s, "ipv6.neighbor.list", json!({}));
    // ::2, ::3 and fe80::1 (a router); ::1 is the router itself.
    assert_eq!(v6["total"], 3, "{v6}");
    assert!(
        v6["rows"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["router"] == true)
    );
}

#[test]
fn bad_parameters_are_refused() {
    let mut s = lab();
    assert!(fails(&mut s, "ip.arp.list", json!({"limit": 0})).contains("1..=5000"));
    assert!(fails(&mut s, "ip.arp.list", json!({"state": "up"})).contains("not one of"));
    assert!(fails(&mut s, "ip.arp.list", json!({"source": "dhcp6"})).contains("dynamic or static"));
    assert!(fails(&mut s, "ip.arp.list", json!({"search": "x".repeat(100)})).contains("at most"));
    let add =
        |mac: &str, ip: &str, i: &str| json!({"address": ip, "mac_address": mac, "interface": i});
    assert!(
        fails(
            &mut s,
            "ip.arp.add",
            add("FF:FF:FF:FF:FF:FF", "10.0.0.50", "ether1")
        )
        .contains("not a host")
    );
    assert!(
        fails(
            &mut s,
            "ip.arp.add",
            add("01:00:5E:00:00:01", "10.0.0.50", "ether1")
        )
        .contains("not a host")
    );
    assert!(
        fails(
            &mut s,
            "ip.arp.add",
            add("02:00:00:00:00:50", "10.0.0.1", "ether1")
        )
        .contains("router's own")
    );
    assert!(
        fails(
            &mut s,
            "ip.arp.add",
            add("02:00:00:00:00:50", "10.0.0.50", "ether99")
        )
        .contains("no interface")
    );
    assert!(
        fails(
            &mut s,
            "ip.arp.add",
            add("02:00:00:00:00:50", "224.0.0.1", "ether1")
        )
        .contains("not a host")
    );
    assert!(fails(&mut s, "ip.arp.add", add("zz", "10.0.0.50", "ether1")).contains("mac_address"));
    assert!(fails(&mut s, "ip.arp.set", json!({"id": "*99"})).contains("static"));
    assert!(
        fails(
            &mut s,
            "ip.arp.make-static",
            json!({"address": "10.0.0.77"})
        )
        .contains("no resolved")
    );
    assert!(
        fails(
            &mut s,
            "ip.arp.settings.set",
            json!({"interface": "ether1", "arp_timeout": "0"})
        )
        .contains("auto or")
    );
}

#[test]
fn static_entries_go_in_the_journal_and_roll_back() {
    let mut s = lab();
    let before = s.store().current_revision();
    let r = run(
        &mut s,
        "ip.arp.add",
        json!({"address": "10.0.0.50", "mac_address": "02:00:00:00:00:50", "interface": "ether1", "comment": "printer"}),
    );
    let id = r["id"].as_str().unwrap().to_owned();
    let row = list(&mut s, json!({"search": "10.0.0.50"}))["rows"][0].clone();
    assert_eq!(row["state"], "permanent");
    assert_eq!(row["source"], "static");
    assert_eq!(row["id"], json!(id));
    assert_eq!(row["flags"], "C");
    assert_eq!(row["comment"], "printer");
    // Duplicate refused; set and disable.
    assert!(fails(&mut s, "ip.arp.add", json!({"address": "10.0.0.50", "mac_address": "02:00:00:00:00:51", "interface": "ether1"})).contains("already"));
    run(
        &mut s,
        "ip.arp.set",
        json!({"id": id, "mac_address": "02:00:00:00:00:51", "disabled": true}),
    );
    let row = list(&mut s, json!({"search": "10.0.0.50"}))["rows"][0].clone();
    assert_eq!(
        (&row["flags"], &row["state"]),
        (&json!("X"), &Value::Null),
        "{row}"
    );
    assert_eq!(row["mac_address"], "02:00:00:00:00:51");
    assert_eq!(s.store().current_revision(), before + 2);
    assert!(
        s.inspect(Some("journal"))
            .unwrap()
            .to_string()
            .contains("ip.arp.add")
    );
    run(&mut s, "config.rollback", json!({"revision": before}));
    assert_eq!(list(&mut s, json!({"search": "10.0.0.50"}))["matched"], 0);
    assert!(s.store().running().ip.arp.entries.is_empty());
}

#[test]
fn make_static_copies_the_learned_mac() {
    let mut s = lab();
    let learned = list(&mut s, json!({"search": "10.0.0.5"}))["rows"][0].clone();
    let r = run(&mut s, "ip.arp.make-static", json!({"address": "10.0.0.5"}));
    assert_eq!(r["mac_address"], learned["mac_address"]);
    let row = list(&mut s, json!({"search": "10.0.0.5"}))["rows"][0].clone();
    assert_eq!(
        (&row["source"], &row["state"]),
        (&json!("static"), &json!("permanent"))
    );
    assert_eq!(list(&mut s, json!({}))["counts"]["sources"]["static"], 1);
    run(&mut s, "ip.arp.remove", json!({"id": r["id"]}));
    assert_eq!(
        list(&mut s, json!({}))["counts"]["sources"].get("static"),
        None
    );
}

#[test]
fn flush_keeps_the_gateway_and_the_management_neighbor() {
    let mut s = lab();
    let me = Caller::new(7, "tls 10.0.0.9:50000")
        .with_principal(Principal::Local)
        .with_link(Link {
            peer: "10.0.0.9:50000".parse().unwrap(),
            local: "10.0.0.1:8729".parse().unwrap(),
        });
    let r = s
        .execute_as(&me, "ip.arp.flush", &json!({"interface": "ether1"}))
        .unwrap();
    let kept: Vec<&str> = r["kept"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| k["address"].as_str().unwrap())
        .collect();
    assert!(kept.contains(&"10.0.0.254"), "{r}");
    assert!(kept.contains(&"10.0.0.9"), "{r}");
    assert!(kept.contains(&"10.0.0.77"), "{r}");
    // 13 on ether1, three kept.
    assert_eq!(r["removed"], 10, "{r}");
    let left = addrs(&list(&mut s, json!({})));
    assert_eq!(left, ["10.0.0.9", "10.0.0.77", "10.0.0.254"]);
    // IPv6 untouched by the IPv4 flush.
    assert_eq!(run(&mut s, "ipv6.neighbor.list", json!({}))["total"], 3);
    let r = run(&mut s, "ipv6.neighbor.flush", json!({}));
    assert_eq!(r["removed"], 3);
}

#[test]
fn risky_modes_ask_and_cutting_the_management_neighbor_is_refused() {
    let mut s = lab();
    let e = fails(
        &mut s,
        "ip.arp.settings.set",
        json!({"interface": "ether1", "arp": "proxy-arp"}),
    );
    assert!(e.contains("confirm=true"), "{e}");
    let r = run(
        &mut s,
        "ip.arp.settings.set",
        json!({"interface": "ether1", "arp": "proxy-arp", "confirm": true, "arp_timeout": "120"}),
    );
    assert_eq!(
        (&r["arp"], &r["arp_timeout"]),
        (&json!("proxy-arp"), &json!(120))
    );
    let p = run(&mut s, "ip.arp.settings.print", json!({}));
    let e1 = p["interfaces"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["interface"] == "ether1")
        .unwrap()
        .clone();
    assert_eq!(
        (&e1["arp"], &e1["entries"]),
        (&json!("proxy-arp"), &json!(13))
    );
    assert_eq!(p["kernel"]["ipv4"]["gc_thresh3"], 1024);

    // reply-only from the management host's port: it would lose us.
    let me = Caller::new(7, "tls 10.0.0.9:50000")
        .with_principal(Principal::Local)
        .with_link(Link {
            peer: "10.0.0.9:50000".parse().unwrap(),
            local: "10.0.0.1:8729".parse().unwrap(),
        });
    let ro = json!({"interface": "ether1", "arp": "reply-only", "confirm": true});
    let e = s
        .execute_as(&me, "ip.arp.settings.set", &ro)
        .unwrap_err()
        .to_string();
    assert!(e.contains("10.0.0.9") && e.contains("make-static"), "{e}");
    // With a static entry for it (and the gateway), allowed.
    for a in ["10.0.0.9", "10.0.0.254"] {
        s.execute_as(&me, "ip.arp.make-static", &json!({"address": a}))
            .unwrap();
    }
    let r = s.execute_as(&me, "ip.arp.settings.set", &ro).unwrap();
    // The other 10 learned and the incomplete gateway lose the router.
    assert_eq!(r["without_static"], 11, "{r}");
    // The lab learns nothing on a reply-only port: the statics stay, and
    // the gateway nobody answers is still being asked for.
    let left = list(&mut s, json!({}));
    assert_eq!(left["total"], 3, "{left}");
    assert_eq!(left["counts"]["states"]["incomplete"], 1);
    assert_eq!(left["counts"]["sources"]["static"], 2);
}

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

#[test]
fn arp_ping_is_a_task_with_replies_and_timeouts() {
    let mut s = lab();
    s.set_runner(std::sync::Arc::new(Threads));
    let started = run(
        &mut s,
        "ip.arp.ping",
        json!({"address": "10.0.0.3", "count": 3, "interval_ms": 100}),
    );
    assert_eq!(
        (&started["interface"], &started["src_address"]),
        (&json!("ether1"), &json!("10.0.0.1"))
    );
    assert!(fails(&mut s, "ip.arp.ping", json!({"address": "198.51.100.1"})).contains("no subnet"));
    let silent = run(
        &mut s,
        "ip.arp.ping",
        json!({"address": "10.0.0.99", "count": 2, "interval_ms": 100, "timeout_ms": 10}),
    );
    let wait = |s: &mut Session, id: &Value| -> Value {
        let t = Instant::now();
        loop {
            let p = run(s, "tool.task.poll", json!({"id": id}));
            if p["done"] == true {
                return p;
            }
            assert!(t.elapsed() < Duration::from_secs(5), "{p}");
            thread::sleep(Duration::from_millis(20));
        }
    };
    let p = wait(&mut s, &started["id"]);
    assert_eq!(p["summary"]["received"], 3, "{p}");
    assert_eq!(p["events"][0]["status"], "reply");
    assert!(p["events"][0]["mac_address"].is_string());
    let p = wait(&mut s, &silent["id"]);
    assert_eq!(
        (&p["summary"]["received"], &p["summary"]["packet_loss"]),
        (&json!(0), &json!(100))
    );
}

#[test]
fn a_gateway_that_does_not_resolve_is_incomplete_in_ip_routes() {
    let mut s = lab();
    let routes = run(&mut s, "ip.route.list", json!({"family": "ipv4"}));
    let by_gw = |gw: &str| {
        routes
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["gateway"] == gw)
            .unwrap()["gateway_status"]
            .clone()
    };
    assert_eq!(by_gw("10.0.0.254"), "reachable");
    assert_eq!(by_gw("10.0.0.77"), "incomplete");
    let page = run(&mut s, "ip.route.page", json!({"family": "ipv4"}));
    let r = page["rows"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["gateway"] == "10.0.0.77")
        .unwrap()
        .clone();
    assert_eq!(r["gateway_status"], "incomplete");
    // Make the lab answer for it (a static entry): resolved again.
    run(
        &mut s,
        "ip.arp.add",
        json!({"address": "10.0.0.77", "mac_address": "02:00:00:00:00:77", "interface": "ether1"}),
    );
    let routes = run(&mut s, "ip.route.list", json!({"family": "ipv4"}));
    let r = routes
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["gateway"] == "10.0.0.77")
        .unwrap()
        .clone();
    assert_eq!(r["gateway_status"], "reachable");
}

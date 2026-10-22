//! G4.2a — `/ip dhcp-server` and `/ip pool`: commands (success, validation,
//! rollback) and the server at run time against the lab's simulated hosts
//! (`proto_dhcp::lab_hosts`), on a simulated clock: leases bound, the
//! squatter's address held as a conflict, names in the DNS, addresses in
//! firewall lists, the journal bringing leases back after a restart.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::storage::MemoryStorage;
use corerouter_engine::{ConfigStorage, Session};
use corerouter_hal::VirtualHal;
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn err(s: &mut Session, id: &str, p: Value) -> String {
    s.execute(id, &p).unwrap_err().to_string()
}

/// A LAN on ether2: 192.168.88.1/24, pool .10–.50, server, network with a
/// zone (and its reverse zone) and a firewall list.
fn lan(s: &mut Session) {
    ok(
        s,
        "ip.address.add",
        json!({"address": "192.168.88.1/24", "interface": "ether2"}),
    );
    ok(s, "ip.dns.zone.add", json!({"name": "lan.example"}));
    ok(
        s,
        "ip.dns.zone.add",
        json!({"name": "88.168.192.in-addr.arpa"}),
    );
    ok(
        s,
        "ip.pool.add",
        json!({"name": "lan", "ranges": "192.168.88.10-192.168.88.50"}),
    );
    ok(
        s,
        "ip.dhcp-server.add",
        json!({"interface": "ether2", "address_pool": "lan", "lease_time": "10m", "address_lists": "lan-hosts"}),
    );
    ok(
        s,
        "ip.dhcp-server.network.add",
        json!({"address": "192.168.88.0/24", "gateway": "192.168.88.1", "dns_server": "192.168.88.1", "domain": "lan.example", "dns_zone": "lan.example"}),
    );
}

/// `secs` of the service clock, 250 ms apart, the Unix clock along.
fn run(s: &mut Session, from_ms: u64, secs: u64) -> u64 {
    let mut ms = from_ms;
    for _ in 0..secs * 4 {
        ms += 250;
        s.tick(1_700_000_000 + ms / 1000);
        s.dhcp_service(ms);
    }
    ms
}

fn leases(s: &mut Session) -> Vec<Value> {
    ok(s, "ip.dhcp-server.lease.print", json!({}))
        .as_array()
        .unwrap()
        .clone()
}

fn status(rows: &[Value], st: &str) -> Vec<Value> {
    rows.iter().filter(|r| r["status"] == st).cloned().collect()
}

#[test]
fn the_lab_hosts_get_leases_names_and_lists() {
    let mut s = Session::virtual_lab();
    lan(&mut s);
    run(&mut s, 0, 5);
    let rows = leases(&mut s);
    let bound = status(&rows, "bound");
    assert_eq!(bound.len(), 4, "{rows:#?}");
    let laptop = bound
        .iter()
        .find(|r| r["host_name"] == "lab-laptop")
        .unwrap();
    assert_eq!(laptop["dynamic"], true);
    assert_eq!(laptop["vendor_class"], "MSFT 5.0");
    assert_eq!(laptop["dns"], "lab-laptop.lan.example");
    assert_eq!(laptop["address_lists"], json!(["lan-hosts"]));
    // The squatter answered ARP for .11: held, with the reason.
    let c = status(&rows, "conflict");
    assert_eq!(c.len(), 1, "{rows:#?}");
    assert_eq!(c[0]["address"], "192.168.88.11");
    assert!(c[0]["reason"].as_str().unwrap().contains("ARP reply"));

    // The DNS has the A and the PTR of each lease (G4.1c-3).
    let (_, dynamic) = s.dns_dynamic();
    let names: Vec<String> = dynamic
        .records
        .iter()
        .map(|r| format!("{} {}", r.record.zone, r.record.name))
        .collect();
    assert!(
        names.iter().any(|n| n == "lan.example lab-laptop"),
        "{names:?}"
    );
    assert!(
        names
            .iter()
            .any(|n| n.starts_with("88.168.192.in-addr.arpa ")),
        "{names:?}"
    );
    // The firewall list has the bound addresses (dynamic entries).
    let list = ok(&mut s, "ip.firewall.address-list.list", json!({}));
    let in_list = list
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["list"] == "lan-hosts")
        .count();
    assert_eq!(in_list, 4);

    // Statistics: DORA counted, pool use, the conflict and the probes.
    let st = ok(&mut s, "ip.dhcp-server.statistics.print", json!({}));
    assert_eq!(st["leases"]["bound"], 4);
    assert_eq!(st["sent"]["ack"], 4);
    assert!(st["received"]["discover"].as_u64().unwrap() >= 4);
    assert_eq!(st["conflicts"], 1);
    assert_eq!(st["pools"][0]["pool"], "lan");
    assert_eq!(st["pools"][0]["bound"], 4);
    assert_eq!(st["pools"][0]["alert"], false);
    assert!(st["latency_us"]["count"].as_u64().unwrap() >= 4);
    let m = ok(&mut s, "system.metrics", json!({}));
    assert_eq!(m["dhcp_server"]["sent"]["ack"], 4);
    let used = ok(&mut s, "ip.pool.used.print", json!({"pool": "lan"}));
    assert!(
        used.as_array().unwrap().len() >= 5,
        "4 bound + the conflict"
    );
    let pools = ok(&mut s, "ip.pool.print", json!({}));
    assert_eq!(pools[0]["size"], 41);
    assert_eq!(pools[0]["used"], 4);
    let srv = ok(&mut s, "ip.dhcp-server.print", json!({}));
    assert_eq!(srv[0]["status"], "running", "{srv}");
    assert_eq!(srv[0]["bound"], 4);
    assert_eq!(srv[0]["lease_time"], "10m");

    // Renewals keep everyone bound past the lease time.
    run(&mut s, 5_000, 900);
    assert_eq!(status(&leases(&mut s), "bound").len(), 4);
}

#[test]
fn make_static_block_release_and_check_status() {
    let mut s = Session::virtual_lab();
    lan(&mut s);
    let ms = run(&mut s, 0, 5);
    let rows = leases(&mut s);
    let printer = rows
        .iter()
        .find(|r| r["host_name"] == "lab-printer")
        .unwrap()
        .clone();
    let ip = printer["address"].as_str().unwrap().to_owned();

    let r = ok(
        &mut s,
        "ip.dhcp-server.lease.make-static",
        json!({"address": ip}),
    );
    assert!(r["id"].as_str().unwrap().starts_with('*'));
    let row = leases(&mut s)
        .into_iter()
        .find(|r| r["address"] == ip)
        .unwrap();
    assert_eq!(
        (row["dynamic"].clone(), row["status"].clone()),
        (json!(false), json!("bound"))
    );
    let cfg = &s.store().running().ip.dhcp_server.leases[0];
    assert_eq!(cfg.host_name, "lab-printer");
    assert_eq!(cfg.client_id, "1:2:1a:b0:2:0:3");
    assert!(
        err(
            &mut s,
            "ip.dhcp-server.lease.make-static",
            json!({"address": ip})
        )
        .contains("static already")
    );

    ok(&mut s, "ip.dhcp-server.lease.block", json!({"address": ip}));
    assert_eq!(
        leases(&mut s)
            .into_iter()
            .find(|r| r["address"] == ip)
            .unwrap()["blocked"],
        true
    );

    // Release: the lease ends now, its DNS and list entries go.
    let tv = leases(&mut s)
        .into_iter()
        .find(|r| r["host_name"] == "lab-tv")
        .unwrap();
    let tv_ip = tv["address"].as_str().unwrap().to_owned();
    ok(
        &mut s,
        "ip.dhcp-server.lease.release",
        json!({"address": tv_ip}),
    );
    assert!(s.dhcp_server_dns(tv_ip.parse().unwrap()).is_none());
    assert!(
        err(
            &mut s,
            "ip.dhcp-server.lease.release",
            json!({"address": tv_ip})
        )
        .contains("released")
    );

    // check-status: the squatter still answers, so the conflict stays.
    ok(
        &mut s,
        "ip.dhcp-server.lease.check-status",
        json!({"address": "192.168.88.11"}),
    );
    run(&mut s, ms, 2);
    let c = leases(&mut s)
        .into_iter()
        .find(|r| r["address"] == "192.168.88.11")
        .unwrap();
    assert_eq!(c["status"], "conflict");
    assert!(
        err(
            &mut s,
            "ip.dhcp-server.lease.check-status",
            json!({"address": ip})
        )
        .contains("not in conflict")
    );
}

#[test]
fn operator_mistakes_are_refused_and_rolled_back() {
    let mut s = Session::virtual_lab();
    lan(&mut s);
    let before = s.store().running().clone();
    // A pool over the gateway and the router's own address.
    let e = err(
        &mut s,
        "ip.pool.set",
        json!({"id": "lan", "ranges": "192.168.88.1-192.168.88.20"}),
    );
    assert!(e.contains("192.168.88.1"), "{e}");
    assert_eq!(s.store().candidate(), &before, "rolled back");
    // Two pools sharing addresses.
    let e = err(
        &mut s,
        "ip.pool.add",
        json!({"name": "b", "ranges": "192.168.88.40-192.168.88.60"}),
    );
    assert!(e.contains("overlaps"), "{e}");
    // References that do not exist.
    assert!(
        err(
            &mut s,
            "ip.dhcp-server.set",
            json!({"id": "dhcp1", "address_pool": "nope"})
        )
        .contains("no pool 'nope'")
    );
    assert!(
        err(
            &mut s,
            "ip.dhcp-server.network.set",
            json!({"id": "192.168.88.0/24", "dns_zone": "nope.example"})
        )
        .contains("no zone")
    );
    assert!(
        err(
            &mut s,
            "ip.dhcp-server.option.add",
            json!({"name": "x", "code": 53, "value": "0x01"})
        )
        .contains("server's own")
    );
    assert!(
        err(
            &mut s,
            "ip.dhcp-server.option.add",
            json!({"name": "x", "code": 66, "value": "bare"})
        )
        .contains("quotes")
    );
    assert!(
        err(&mut s, "ip.dhcp-server.add", json!({"interface": "ether2"}))
            .contains("already serves")
    );
    assert!(err(&mut s, "ip.pool.remove", json!({"id": "lan"})).contains("in use by server dhcp1"));
    assert!(
        err(
            &mut s,
            "ip.dhcp-server.lease.add",
            json!({"address": "192.168.88.1", "mac_address": "02:00:00:00:00:01"})
        )
        .contains("router's address")
    );
    assert!(
        err(
            &mut s,
            "ip.dhcp-server.lease.add",
            json!({"address": "192.168.88.60"})
        )
        .contains("MAC or a client id")
    );
    assert_eq!(s.store().running(), &before);

    // A warning is not an error: a server where a DHCP client runs.
    ok(
        &mut s,
        "ip.address.add",
        json!({"address": "10.9.0.1/24", "interface": "ether3"}),
    );
    ok(&mut s, "ip.dhcp-client.add", json!({"interface": "ether3"}));
    let r = ok(&mut s, "ip.dhcp-server.add", json!({"interface": "ether3"}));
    assert!(
        r["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("DHCP client")),
        "{r}"
    );
    let nets = ok(&mut s, "ip.dhcp-server.network.print", json!({}));
    let labels: Vec<&str> = nets[0]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["label"].as_str().unwrap())
        .collect();
    assert!(
        labels.contains(&"gateway") && labels.contains(&"pool") && labels.contains(&"DNS"),
        "{labels:?}"
    );
}

#[test]
fn options_sets_matchers_and_alerts() {
    let mut s = Session::virtual_lab();
    lan(&mut s);
    let r = ok(
        &mut s,
        "ip.dhcp-server.option.add",
        json!({"name": "tftp", "code": 66, "value": "'tftp.lan'"}),
    );
    assert_eq!(r["raw_value"], "0x746674702e6c616e");
    ok(
        &mut s,
        "ip.dhcp-server.option-set.add",
        json!({"name": "pcs", "options": "tftp"}),
    );
    ok(
        &mut s,
        "ip.dhcp-server.matcher.add",
        json!({"name": "windows", "code": 60, "value": "'MSFT'", "matching_type": "substring", "option_set": "pcs"}),
    );
    assert!(
        err(
            &mut s,
            "ip.dhcp-server.option.remove",
            json!({"id": "tftp"})
        )
        .contains("option set pcs")
    );
    assert!(
        err(
            &mut s,
            "ip.dhcp-server.option-set.remove",
            json!({"id": "pcs"})
        )
        .contains("matcher windows")
    );
    let m = ok(&mut s, "ip.dhcp-server.matcher.print", json!({}));
    assert_eq!(m[0]["server"], "all");

    ok(
        &mut s,
        "ip.dhcp-server.alert.add",
        json!({"interface": "ether2"}),
    );
    run(&mut s, 0, 3);
    let a = ok(&mut s, "ip.dhcp-server.alert.print", json!({}));
    let seen = a[0]["unknown_server"].as_array().unwrap();
    assert_eq!(seen.len(), 1, "the lab's rogue server: {a}");
    assert_eq!(seen[0]["mac"], "02:BA:D0:00:00:02");
    let log = s.log_since(0);
    assert!(
        log.iter().any(|e| e.topics.iter().any(|t| t == "critical")
            && e.message.contains("unknown DHCP server"))
    );
    ok(
        &mut s,
        "ip.dhcp-server.alert.set",
        json!({"id": "ether2", "valid_server": "02:BA:D0:00:00:02"}),
    );
    ok(
        &mut s,
        "ip.dhcp-server.alert.reset-alert",
        json!({"id": "ether2"}),
    );
    run(&mut s, 3_000, 70);
    let a = ok(&mut s, "ip.dhcp-server.alert.print", json!({}));
    assert_eq!(a[0]["unknown_server"], json!([]), "a valid server now");
}

#[test]
fn leases_survive_a_restart_through_the_journal() {
    let storage = MemoryStorage::default();
    let mut s = Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()));
    lan(&mut s);
    run(&mut s, 0, 5);
    let before: Vec<(Value, Value)> = status(&leases(&mut s), "bound")
        .iter()
        .map(|r| (r["address"].clone(), r["mac_address"].clone()))
        .collect();
    assert_eq!(before.len(), 4);
    let journal = storage
        .clone()
        .load_journal("dhcp-leases")
        .unwrap()
        .unwrap();
    assert!(journal.lines().count() >= 5, "{journal}");
    drop(s);

    // A "reboot": the same storage, a new session. Before any message, the
    // leases are back.
    let mut s = Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()));
    s.tick(1_700_000_010);
    s.dhcp_service(10);
    let after: Vec<(Value, Value)> = status(&leases(&mut s), "bound")
        .iter()
        .map(|r| (r["address"].clone(), r["mac_address"].clone()))
        .collect();
    assert_eq!(after, before);
}

#[test]
fn a_removed_server_ends_its_leases() {
    let mut s = Session::virtual_lab();
    lan(&mut s);
    let ms = run(&mut s, 0, 5);
    assert_eq!(status(&leases(&mut s), "bound").len(), 4);
    ok(&mut s, "ip.dhcp-server.remove", json!({"id": "dhcp1"}));
    run(&mut s, ms, 1);
    assert!(status(&leases(&mut s), "bound").is_empty());
    let (_, dynamic) = s.dns_dynamic();
    assert!(dynamic.records.is_empty(), "names gone with the leases");
}

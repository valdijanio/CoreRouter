//! G1.27f / G3.6g — check-gateway on static routes, in the virtual lab:
//! the commands (success, validation, rollback), the routes grouped by
//! gateway, the route that leaves the data plane while its gateway is down
//! and the backup that takes over, the hold-down of a flapping gateway,
//! and `bfd` following the BFD service's sessions. The probes themselves
//! run on the daemon's `route-check` thread (netns test there): here the
//! results are handed to the engine as that thread would.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::Session;
use corerouter_engine::gateway_check::{ProbeHow, ProbeTarget, Target};
use corerouter_model::bfd::{BfdSessionStatus, BfdState};
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p).unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn fails(s: &mut Session, id: &str, p: Value, needle: &str) {
    let before = s.store().candidate().clone();
    let err = s.execute(id, &p).unwrap_err().to_string();
    assert!(err.contains(needle), "{id} {p}: '{err}' lacks '{needle}'");
    assert_eq!(s.store().candidate(), &before, "{id} left changes behind");
}

/// ether1 = 10.0.0.2/24 + 2001:db8::2/64 (primary uplink), ether2 =
/// 10.9.0.2/24 (backup uplink).
fn lab() -> Session {
    let mut s = Session::virtual_lab();
    for (a, i) in [("10.0.0.2/24", "ether1"), ("2001:db8::2/64", "ether1"), ("10.9.0.2/24", "ether2")] {
        ok(&mut s, "ip.address.add", json!({"address": a, "interface": i}));
    }
    s
}

fn add(s: &mut Session, p: Value) -> String {
    ok(s, "ip.route.add", p)["id"].as_str().unwrap().to_owned()
}

fn row(s: &mut Session, id: &str) -> Value {
    ok(s, "ip.route.list", json!({}))
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == id)
        .cloned()
        .unwrap_or_else(|| panic!("{id} not listed"))
}

/// Report every probe target as answered (or not) at `now`.
fn report(s: &mut Session, targets: &[ProbeTarget], answered: bool, now: u64) {
    let r: Vec<(Target, bool)> = targets.iter().map(|t| (t.target.clone(), answered)).collect();
    s.route_check_report(&r, Some(now));
}

/// Kernel routes to `0.0.0.0/0` (as the virtual platform holds them).
fn kernel_defaults(s: &mut Session, key: &str) -> Vec<String> {
    let d = ok(s, "ip.route.detail", json!({"key": key}));
    d["kernel"]["present"]
        .as_array()
        .map(|a| a.iter().map(|v| v.as_str().unwrap().to_owned()).collect())
        .unwrap_or_default()
}

#[test]
fn ping_check_withdraws_the_route_and_the_backup_takes_over() {
    let mut s = lab();
    let main = add(
        &mut s,
        json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1", "check_gateway": "ping"}),
    );
    let backup = add(&mut s, json!({"dst_address": "0.0.0.0/0", "gateway": "10.9.0.1", "distance": 10}));
    // No daemon runs the checks yet: said so, the route stays.
    let r = row(&mut s, &main);
    assert_eq!(r["check_gateway"]["status"], "not-checked", "{r}");
    assert_eq!(r["active"], true);

    let targets = s.route_check_targets(Some(0));
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].how, ProbeHow::Ping { device: None });
    assert_eq!(row(&mut s, &main)["check_gateway"]["status"], "checking");
    report(&mut s, &targets, true, 1_000);
    assert_eq!(row(&mut s, &main)["check_gateway"]["status"], "reachable");
    assert_eq!(kernel_defaults(&mut s, &backup).len(), 2);

    // RouterOS: one miss is not enough, two are.
    report(&mut s, &targets, false, 10_000);
    let r = row(&mut s, &main);
    assert_eq!((r["active"].clone(), r["check_gateway"]["misses"].clone()), (json!(true), json!(1)));
    report(&mut s, &targets, false, 20_000);
    let r = row(&mut s, &main);
    assert_eq!(r["state"], "inactive", "{r}");
    assert_eq!(r["check_gateway"]["status"], "unreachable");
    assert_eq!(r["reason_id"], "check-gateway-down", "{r}");
    assert!(r["reason"].as_str().unwrap().contains("check-gateway=ping"), "{r}");
    assert_eq!(r["origin"], "static");
    let b = row(&mut s, &backup);
    assert_eq!(b["active"], true, "{b}");
    // Out of the kernel: only the backup is left there.
    let k = kernel_defaults(&mut s, &backup);
    assert_eq!(k.len(), 1, "{k:?}");
    assert!(k[0].contains("10.9.0.1"), "{k:?}");
    let d = ok(&mut s, "ip.route.detail", json!({"key": main}));
    assert!(d["kernel"]["note"].as_str().unwrap().contains("check-gateway"), "{d}");
    assert_eq!(d["check_gateway"]["history"][0]["to"], "down", "{d}");

    // Back at the first answer (first down of the window).
    report(&mut s, &targets, true, 30_000);
    assert_eq!(row(&mut s, &main)["active"], true);
    assert_eq!(kernel_defaults(&mut s, &backup).len(), 2);
    let h = ok(&mut s, "ip.route.check.history", json!({}));
    let to: Vec<&str> = h.as_array().unwrap().iter().map(|e| e["to"].as_str().unwrap()).collect();
    assert_eq!(to, ["down", "up"]);
    assert!(h[0]["message"].as_str().unwrap().contains("did not answer 2 ping checks"), "{h}");
}

#[test]
fn routes_through_one_gateway_share_one_probe() {
    let mut s = lab();
    for dst in ["10.10.0.0/16", "10.11.0.0/16", "10.12.0.0/16"] {
        add(&mut s, json!({"dst_address": dst, "gateway": "10.0.0.1", "check_gateway": "arp"}));
    }
    add(&mut s, json!({"dst_address": "10.20.0.0/16", "gateway": "10.0.0.1", "check_gateway": "ping"}));
    add(&mut s, json!({"dst_address": "10.30.0.0/16", "gateway": "10.0.0.1"}));
    let targets = s.route_check_targets(Some(0));
    assert_eq!(targets.len(), 2, "{targets:?}");
    let arp = targets.iter().find(|t| matches!(t.how, ProbeHow::Arp { .. })).unwrap();
    assert_eq!(
        arp.how,
        ProbeHow::Arp { link: "ether1".parse().unwrap(), src: "10.0.0.2".parse().unwrap() }
    );
    let list = ok(&mut s, "ip.route.check.list", json!({}));
    let arp_row = list.as_array().unwrap().iter().find(|r| r["method"] == "arp").unwrap();
    assert_eq!(arp_row["routes"], 3);
    // One down: the three routes leave together, the ping one stays.
    report(&mut s, std::slice::from_ref(arp), false, 10_000);
    report(&mut s, std::slice::from_ref(arp), false, 20_000);
    let rows = ok(&mut s, "ip.route.list", json!({"origin": "static"}));
    let inactive: Vec<&str> = rows
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| r["state"] == "inactive")
        .map(|r| r["dst_address"].as_str().unwrap())
        .collect();
    assert_eq!(inactive, ["10.10.0.0/16", "10.11.0.0/16", "10.12.0.0/16"]);
    // A route that no longer checks comes back at the next sync.
    let id = rows[0]["id"].as_str().unwrap().to_owned();
    ok(&mut s, "ip.route.set", json!({"id": id, "check_gateway": "none"}));
    s.route_check_targets(Some(21_000));
    assert_eq!(row(&mut s, &id)["state"], "active");
    // Removing the last routes of a down target brings nothing back by
    // mistake and leaves no target behind.
    for r in rows.as_array().unwrap() {
        if r["check_gateway"]["method"] == "arp" {
            ok(&mut s, "ip.route.remove", json!({"id": r["id"]}));
        }
    }
    s.route_check_targets(Some(22_000));
    let list = ok(&mut s, "ip.route.check.list", json!({}));
    assert_eq!(list.as_array().unwrap().len(), 1, "{list}");
}

#[test]
fn a_flapping_gateway_is_held_down() {
    let mut s = lab();
    let id = add(&mut s, json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1", "check_gateway": "ping"}));
    let t = s.route_check_targets(Some(0));
    let mut now = 0;
    let cycle = |s: &mut Session, now: &mut u64| {
        report(s, &t, false, *now);
        report(s, &t, false, *now + 10_000);
        *now += 20_000;
        report(s, &t, true, *now);
    };
    cycle(&mut s, &mut now);
    assert_eq!(row(&mut s, &id)["active"], true);
    now += 10_000;
    cycle(&mut s, &mut now);
    // Second down in 15 min: answering, but held 10 s.
    let r = row(&mut s, &id);
    assert_eq!(r["active"], false, "{r}");
    assert_eq!(r["check_gateway"]["hold_down_secs"], 10, "{r}");
    report(&mut s, &t, true, now + 10_000);
    assert_eq!(row(&mut s, &id)["active"], true);
}

#[test]
fn bfd_check_follows_the_session() {
    let mut s = lab();
    let id = add(
        &mut s,
        json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1", "check_gateway": "bfd", "bfd_profile": "fast"}),
    );
    // The BFD service is asked for a session to the gateway.
    let sessions = ok(&mut s, "routing.bfd.session.list", json!({}));
    let sess = &sessions["sessions"][0];
    assert_eq!(sess["peer"], "10.0.0.1", "{sessions}");
    assert_eq!(sess["profile"], "fast");
    assert_eq!(sess["users"][0], "route 0.0.0.0/0");
    // No probe for the route-check thread.
    assert!(s.route_check_targets(Some(0)).is_empty());
    let r = row(&mut s, &id);
    assert_eq!((r["check_gateway"]["method"].clone(), r["check_gateway"]["status"].clone()), (json!("bfd"), json!("checking")));
    assert_eq!(r["check_gateway"]["bfd_profile"], "fast");
    // A session still coming up does not pull the route.
    let peer = "10.0.0.1".parse().unwrap();
    s.route_check_bfd_event(peer, false, None, false);
    assert_eq!(row(&mut s, &id)["active"], true);
    s.route_check_bfd_event(peer, false, None, true);
    assert_eq!(row(&mut s, &id)["check_gateway"]["status"], "reachable");
    // Down: at once (BFD already waited its detect time).
    s.route_check_bfd_event(peer, false, None, false);
    let r = row(&mut s, &id);
    assert_eq!(r["state"], "inactive", "{r}");
    assert!(r["reason"].as_str().unwrap().contains("BFD session"), "{r}");
    // A multihop session to the same address is another session.
    s.route_check_bfd_event(peer, true, None, true);
    assert_eq!(row(&mut s, &id)["state"], "inactive");
    // The published session list counts too (the service's snapshot).
    if let Some(st) = s.ext_mut::<BfdState>() {
        st.sessions.push(BfdSessionStatus {
            peer: Some(peer),
            state: "up".into(),
            ..BfdSessionStatus::default()
        });
    }
    s.route_check_targets(Some(60_000));
    assert_eq!(row(&mut s, &id)["state"], "active");
}

#[test]
fn bfd_that_never_comes_up_counts_as_down_after_the_grace() {
    let mut s = lab();
    let id = add(&mut s, json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1", "check_gateway": "bfd"}));
    s.route_check_targets(Some(0));
    s.route_check_targets(Some(4_000));
    assert_eq!(row(&mut s, &id)["active"], true);
    s.route_check_targets(Some(6_000));
    assert_eq!(row(&mut s, &id)["state"], "inactive");
}

#[test]
fn check_gateway_is_validated() {
    let mut s = lab();
    fails(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "10.1.0.0/16", "gateway": "ether1", "check_gateway": "ping"}),
        "needs a gateway address",
    );
    fails(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "2001:db8:1::/48", "gateway": "2001:db8::1", "check_gateway": "arp"}),
        "arp checks IPv4 gateways",
    );
    fails(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "10.1.0.0/16", "gateway": "10.0.0.1", "check_gateway": "bfd", "bfd_profile": "nope"}),
        "no BFD profile 'nope'",
    );
    fails(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "10.1.0.0/16", "gateway": "10.0.0.1", "bfd_profile": "fast"}),
        "only with check_gateway=bfd",
    );
    fails(
        &mut s,
        "ip.route.add",
        json!({"dst_address": "10.1.0.0/16", "gateway": "10.0.0.1", "check_gateway": "icmp"}),
        "expected none, arp, ping or bfd",
    );
    // IPv6 gateways are pinged.
    add(&mut s, json!({"dst_address": "2001:db8:1::/48", "gateway": "2001:db8::1", "check_gateway": "ping"}));
    // Leaving bfd drops the profile.
    let id = add(
        &mut s,
        json!({"dst_address": "10.1.0.0/16", "gateway": "10.0.0.1", "check_gateway": "bfd", "bfd_profile": "fast"}),
    );
    ok(&mut s, "ip.route.set", json!({"id": id, "check_gateway": "ping"}));
    let r = s.store().candidate().ip.routes.iter().find(|r| r.id.to_string() == id).cloned().unwrap();
    assert!(r.bfd_profile.is_empty());
    // A profile a route uses cannot be removed.
    ok(&mut s, "routing.bfd.profile.add", json!({"name": "wan", "min_tx": 100, "multiplier": 3}));
    ok(&mut s, "ip.route.set", json!({"id": id, "check_gateway": "bfd", "bfd_profile": "wan"}));
    fails(&mut s, "routing.bfd.profile.remove", json!({"id": "wan"}), "used by route");
}

#[test]
fn a_transaction_rolls_the_check_back() {
    let mut s = lab();
    let id = add(&mut s, json!({"dst_address": "0.0.0.0/0", "gateway": "10.0.0.1"}));
    ok(&mut s, "config.mode.set", json!({"mode": "transactional"}));
    ok(&mut s, "ip.route.set", json!({"id": id, "check_gateway": "arp"}));
    ok(&mut s, "config.discard", json!({}));
    let r = row(&mut s, &id);
    assert_eq!(r["check_gateway"], Value::Null, "{r}");
    assert!(s.route_check_targets(Some(0)).is_empty());
}

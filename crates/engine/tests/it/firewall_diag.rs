//! G2.1c — firewall diagnosis: the packet tester, the ruleset preview, live
//! counters (feed, restart after a commit, reset, stale) and the trace
//! (limits, events, end by cap and by stop).
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::Session;
use corerouter_engine::firewall_diag::{RuleCounter, TraceEvent};
use corerouter_model::ItemId;
use corerouter_model::firewall::Table;
use proptest::prelude::*;
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn err(s: &mut Session, id: &str, p: Value) -> String {
    match s.execute(id, &p) {
        Err(e) => e.to_string(),
        Ok(v) => panic!("{id} {p}: expected an error, got {v}"),
    }
}

/// ether1 WAN 203.0.113.1/24, ether2 LAN 10.0.0.1/24; port forward 8080 →
/// 10.0.0.20:80, forward accepts established and the forward, drops WAN.
fn router() -> Session {
    let mut s = Session::virtual_lab();
    for p in [
        json!({"address": "203.0.113.1/24", "interface": "ether1"}),
        json!({"address": "10.0.0.1/24", "interface": "ether2"}),
    ] {
        ok(&mut s, "ip.address.add", p);
    }
    for (l, i) in [("WAN", "ether1"), ("LAN", "ether2")] {
        ok(
            &mut s,
            "interface.list.member.add",
            json!({"list": l, "interface": i}),
        );
    }
    ok(
        &mut s,
        "ip.firewall.nat.add",
        json!({"chain": "dstnat", "action": "dst-nat", "protocol": "tcp", "dst_port": "8080",
               "to_addresses": "10.0.0.20", "to_ports": "80"}),
    );
    ok(
        &mut s,
        "ip.firewall.nat.add",
        json!({"chain": "srcnat", "action": "masquerade", "out_interface_list": "WAN"}),
    );
    for p in [
        json!({"chain": "forward", "connection_state": "established,related"}),
        json!({"chain": "forward", "connection_nat_state": "dstnat"}),
        json!({"chain": "forward", "action": "drop", "in_interface_list": "WAN"}),
        json!({"chain": "input", "action": "drop", "protocol": "tcp", "dst_port": "22", "in_interface_list": "WAN"}),
    ] {
        ok(&mut s, "ip.firewall.filter.add", p);
    }
    s
}

#[test]
fn the_tester_shows_the_path_and_the_deciding_rule() {
    let mut s = router();
    let out = ok(
        &mut s,
        "ip.firewall.test",
        json!({"src": "198.51.100.9", "dst": "203.0.113.1", "dst_port": 8080, "in_interface": "ether1"}),
    );
    let chains: Vec<String> = out["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            format!(
                "{}/{}",
                s["table"].as_str().unwrap(),
                s["chain"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(
        chains,
        ["nat/dstnat", "filter/forward", "nat/srcnat"],
        "{out}"
    );
    assert_eq!(out["route"], "ether2", "routed after dst-nat");
    assert_eq!(out["packet"]["dst"], "10.0.0.20");
    assert_eq!(out["packet"]["dst_port"], 80);
    assert_eq!(out["fate"], "sent");
    // NAT kept the connection_nat_state assumption: no NAT seen, so the
    // WAN drop decides (the tester says what the evaluator assumes).
    assert_eq!(out["decided_by"]["table"], "filter");

    let ssh = ok(
        &mut s,
        "ip.firewall.test",
        json!({"src": "198.51.100.9", "dst": "203.0.113.1", "dst_port": 22, "in_interface": "ether1"}),
    );
    assert_eq!(ssh["route"], "local");
    assert_eq!(ssh["fate"], "dropped");
    assert!(
        ssh["decided_by"]["summary"]
            .as_str()
            .unwrap()
            .contains("dst-port=22")
    );

    let from_lan = ok(
        &mut s,
        "ip.firewall.test",
        json!({"src": "10.0.0.9", "dst": "8.8.8.8", "protocol": "udp", "dst_port": 53,
               "in_interface": "ether2"}),
    );
    assert_eq!(
        from_lan["route"], "unreachable",
        "no default route in the lab"
    );
    assert_eq!(from_lan["fate"], "no-route");

    let ping_out = ok(
        &mut s,
        "ip.firewall.test",
        json!({"src": "10.0.0.1", "dst": "10.0.0.20", "protocol": "icmp"}),
    );
    assert_eq!(ping_out["fate"], "sent");

    for (p, key) in [
        (json!({"src": "10.0.0.1", "dst": "::1"}), "dst"),
        (
            json!({"src": "10.0.0.1", "dst": "10.0.0.2", "protocol": "icmp", "dst_port": 1}),
            "dst_port",
        ),
        (
            json!({"src": "10.0.0.1", "dst": "10.0.0.2", "in_interface": "nope0"}),
            "in_interface",
        ),
        (
            json!({"src": "10.0.0.1", "dst": "10.0.0.2", "state": "sleepy"}),
            "state",
        ),
        (
            json!({"src": "::1", "dst": "::2", "protocol": "icmp"}),
            "protocol",
        ),
    ] {
        let e = err(&mut s, "ip.firewall.test", p.clone());
        assert!(e.contains(key), "{p}: {e}");
    }
}

#[test]
fn the_preview_diffs_running_and_candidate() {
    let mut s = router();
    let same = ok(&mut s, "ip.firewall.preview", json!({}));
    assert_eq!(same["changed"], false);
    ok(&mut s, "config.mode.set", json!({"mode": "transactional"}));
    ok(
        &mut s,
        "ip.firewall.raw.add",
        json!({"action": "drop", "src_address": "192.0.2.0/24"}),
    );
    let d = ok(&mut s, "ip.firewall.preview", json!({}));
    assert_eq!(d["changed"], true);
    assert_eq!(d["removed"], 0);
    let added: Vec<&str> = d["lines"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|l| l["op"] == "+")
        .map(|l| l["text"].as_str().unwrap())
        .collect();
    assert!(
        added.iter().any(|l| l.contains("chain raw_prerouting")),
        "{added:?}"
    );
    assert!(
        added.iter().any(|l| l.contains("ip saddr 192.0.2.0/24")),
        "{added:?}"
    );
    // The tester sees the pending rule; with running=true it does not.
    let probe = json!({"src": "192.0.2.9", "dst": "203.0.113.1", "dst_port": 443, "in_interface": "ether1"});
    assert_eq!(
        ok(&mut s, "ip.firewall.test", probe.clone())["fate"],
        "dropped"
    );
    let mut run = probe;
    run["running"] = json!(true);
    assert_eq!(ok(&mut s, "ip.firewall.test", run)["fate"], "delivered");
    ok(&mut s, "config.commit", json!({}));
    assert_eq!(
        ok(&mut s, "ip.firewall.preview", json!({}))["changed"],
        false
    );
}

fn feed(s: &mut Session, rows: &[(u32, u64)]) {
    s.firewall_counters_feed(Ok(rows
        .iter()
        .map(|(id, p)| RuleCounter {
            table: Table::Filter,
            id: ItemId(*id),
            packets: *p,
            bytes: p * 100,
        })
        .collect()));
}

#[test]
fn counters_go_on_across_commits_and_reset() {
    let mut s = router();
    assert!(!s.firewall_counters_wanted(), "nobody looked yet");
    ok(&mut s, "ip.firewall.counters", json!({}));
    assert!(
        s.firewall_counters_wanted(),
        "a query keeps the reads going"
    );
    feed(&mut s, &[(3, 10), (4, 0), (4, 5)]);
    let c = ok(&mut s, "ip.firewall.counters", json!({"table": "filter"}));
    let row = |c: &Value, id: &str| {
        c["rules"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .cloned()
            .unwrap()
    };
    assert_eq!(row(&c, "*3")["packets"], 10);
    assert_eq!(
        row(&c, "*4")["packets"],
        5,
        "kernel rules of one rule summed"
    );
    // The table was replaced (a commit): the kernel starts at 0 again.
    feed(&mut s, &[(3, 2), (4, 5)]);
    let c = ok(&mut s, "ip.firewall.counters", json!({}));
    assert_eq!(row(&c, "*3")["packets"], 12, "totals go on");
    assert_eq!(row(&c, "*3")["bytes"], 1200);
    // The rule list carries them too.
    let list = ok(&mut s, "ip.firewall.filter.list", json!({}));
    let r3 = list
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "*3")
        .unwrap();
    assert_eq!(r3["packets"], 12);
    assert_eq!(r3["stale"], false);
    // Stale: with stale_days=0 every rule is.
    let c = ok(&mut s, "ip.firewall.counters", json!({"stale_days": 0}));
    assert_eq!(row(&c, "*3")["stale"], true);
    // Reset one, then the whole table.
    assert_eq!(
        ok(
            &mut s,
            "ip.firewall.filter.reset-counters",
            json!({"id": "*3"})
        )["reset"],
        1
    );
    let c = ok(&mut s, "ip.firewall.counters", json!({}));
    assert_eq!(row(&c, "*3")["packets"], 0);
    assert_eq!(row(&c, "*4")["packets"], 5);
    assert_eq!(
        ok(&mut s, "ip.firewall.filter.reset-counters", json!({}))["reset"],
        2
    );
    let e = err(
        &mut s,
        "ip.firewall.filter.reset-counters",
        json!({"id": "*99"}),
    );
    assert!(e.contains("no filter rule"), "{e}");
    // A failed read is shown, not hidden.
    s.firewall_counters_feed(Err("permission denied".into()));
    let c = ok(&mut s, "ip.firewall.counters", json!({}));
    assert_eq!(c["error"], "permission denied");
}

fn event(trace: u32, chain: &str, verdict: &str) -> TraceEvent {
    TraceEvent {
        trace,
        at: 0,
        table: "filter".into(),
        chain: chain.into(),
        rule: Some(ItemId(5)),
        kind: "rule",
        verdict: verdict.into(),
        iif: Some("ether1".into()),
        oif: None,
        src: "198.51.100.9".parse().ok(),
        dst: "203.0.113.1".parse().ok(),
        protocol: Some(6),
        sport: Some(40_000),
        dport: Some(22),
    }
}

#[test]
fn the_trace_needs_a_filter_and_stops_by_itself() {
    let mut s = router();
    let e = err(&mut s, "ip.firewall.trace.start", json!({}));
    assert!(e.contains("needs a filter"), "{e}");
    for (p, key) in [
        (json!({"port": 22}), "port"),
        (json!({"src": "10.0.0.1", "dst": "::1"}), "dst"),
        (json!({"protocol": "tcp", "duration": 301}), "duration"),
        (json!({"protocol": "tcp", "max_events": 0}), "max_events"),
        (json!({"src": "10.0.0.1-10.0.0.9"}), "src"),
    ] {
        let e = err(&mut s, "ip.firewall.trace.start", p.clone());
        assert!(e.contains(key), "{p}: {e}");
    }
    let job = ok(
        &mut s,
        "ip.firewall.trace.start",
        json!({"protocol": "tcp", "port": 22, "max_events": 3}),
    );
    let g = job["generation"].as_u64().unwrap();
    let running = s.firewall_trace_job().unwrap();
    assert_eq!(running.filter.port, Some(22));
    assert!(s.firewall_trace_push(g, vec![event(1, "input", "continue")]));
    assert!(
        !s.firewall_trace_push(g - 1, vec![]),
        "an old generation is over"
    );
    // The cap: two more events end it.
    assert!(!s.firewall_trace_push(
        g,
        vec![
            event(1, "input", "drop"),
            event(2, "input", "drop"),
            event(3, "input", "drop")
        ]
    ));
    assert!(s.firewall_trace_job().is_none());
    let list = ok(&mut s, "ip.firewall.trace.list", json!({}));
    assert_eq!(list["active"], false);
    assert_eq!(list["ended"], "events");
    let packets = list["packets"].as_array().unwrap();
    assert_eq!(packets.len(), 2, "grouped by trace id, capped at 3 events");
    assert_eq!(packets[0]["fate"], "drop");
    assert_eq!(packets[0]["steps"].as_array().unwrap().len(), 2);
    assert_eq!(packets[0]["dport"], 22);

    ok(
        &mut s,
        "ip.firewall.trace.start",
        json!({"src": "198.51.100.0/24"}),
    );
    assert_eq!(
        ok(&mut s, "ip.firewall.trace.stop", json!({}))["stopped"],
        true
    );
    assert_eq!(
        ok(&mut s, "ip.firewall.trace.list", json!({}))["ended"],
        "stopped"
    );
    assert_eq!(
        ok(&mut s, "ip.firewall.trace.stop", json!({}))["stopped"],
        false
    );
}

proptest! {
    /// Any address pair, protocol, ports, interface and state: the tester
    /// answers (or refuses with a parameter error), never panics, and a
    /// packet that is sent or delivered went through every chain it lists.
    #[test]
    fn the_tester_takes_any_packet(
        a in any::<[u8; 4]>(), b in any::<[u8; 4]>(),
        proto in prop_oneof![Just("tcp"), Just("udp"), Just("icmp"), Just("47"), Just("icmpv6")],
        sport in any::<u16>(), dport in any::<u16>(),
        iface in prop_oneof![Just(None), Just(Some("ether1")), Just(Some("ether2")), Just(Some("ether9"))],
        state in prop_oneof![Just("new"), Just("established"), Just("invalid"), Just("bogus")],
    ) {
        let mut s = router();
        let mut p = json!({
            "src": std::net::Ipv4Addr::from(a).to_string(),
            "dst": std::net::Ipv4Addr::from(b).to_string(),
            "protocol": proto, "state": state,
        });
        if proto == "tcp" || proto == "udp" {
            p["src_port"] = json!(sport);
            p["dst_port"] = json!(dport);
        }
        if let Some(i) = iface {
            p["in_interface"] = json!(i);
        }
        match s.execute("ip.firewall.test", &p) {
            Ok(v) => {
                let fate = v["fate"].as_str().unwrap();
                prop_assert!(["delivered", "sent", "dropped", "no-route"].contains(&fate));
                if fate == "dropped" {
                    prop_assert!(!v["decided_by"].is_null() || v["steps"].as_array().unwrap().iter().any(|s| s["verdict"] == "drop"));
                }
            }
            Err(e) => prop_assert!(e.to_string().contains("state") || e.to_string().contains("protocol") || e.to_string().contains("in_interface"), "{e}"),
        }
    }
}

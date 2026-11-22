//! G1.31d — `action=change-mss` in the mangle: the RouterOS rules
//! (protocol=tcp, tcp-flags=syn, clamp-to-pmtu after routing), the warnings
//! of a rule that changes nothing, the list/summary and the rollback.
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]

use corerouter_engine::{EngineError, Session};
use serde_json::{Value, json};

fn ok(s: &mut Session, id: &str, p: Value) -> Value {
    s.execute(id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

fn bad(s: &mut Session, id: &str, p: Value) -> (String, String) {
    match s.execute(id, &p) {
        Err(EngineError::BadParam { param, reason }) => (param, reason),
        other => panic!("{id} {p}: expected a parameter error, got {other:?}"),
    }
}

const ADD: &str = "ip.firewall.mangle.add";

#[test]
fn clamp_rule_is_added_listed_and_rendered() {
    let mut s = Session::virtual_lab();
    let r = ok(
        &mut s,
        ADD,
        json!({"chain": "forward", "action": "change-mss", "new_mss": "clamp-to-pmtu",
               "protocol": "tcp", "tcp_flags": "syn", "out_interface": "ether1"}),
    );
    let id = r["id"].as_str().unwrap().to_owned();
    // ether1 has MTU 1500: clamping to it changes nothing.
    assert!(
        r["warnings"][0]
            .as_str()
            .unwrap()
            .contains("clamp-to-pmtu changes nothing on ether1"),
        "{r}"
    );
    let list = ok(&mut s, "ip.firewall.mangle.list", json!({}));
    let row = &list[0];
    assert_eq!(row["action"], "change-mss");
    assert_eq!(row["new_mss"], "clamp-to-pmtu");
    assert_eq!(row["tcp_flags"], "syn");
    assert!(
        row["summary"]
            .as_str()
            .unwrap()
            .contains("tcp-flags=syn new-mss=clamp-to-pmtu"),
        "{row}"
    );
    assert!(
        row["description"].as_str().unwrap().contains("Baixa o MSS"),
        "{row}"
    );
    let script = corerouter_firewall::script(s.store().running(), &[]);
    assert!(
        script.contains("tcp flags & syn == syn counter tcp option maxseg size set rt mtu"),
        "{script}"
    );
    // A fixed value, then passthrough off.
    let r = ok(
        &mut s,
        "ip.firewall.mangle.set",
        json!({"id": id, "new_mss": "1380", "passthrough": false}),
    );
    assert_eq!(r["warnings"], json!([]), "{r}");
    let script = corerouter_firewall::script(s.store().running(), &[]);
    assert!(
        script.contains("tcp option maxseg size set 1380 accept"),
        "{script}"
    );
}

#[test]
fn routeros_requirements_are_errors() {
    let mut s = Session::virtual_lab();
    let base = |extra: Value| {
        let mut p = json!({"chain": "forward", "action": "change-mss", "new_mss": "1400"});
        for (k, v) in extra.as_object().unwrap() {
            p[k] = v.clone();
        }
        p
    };
    let (param, why) = bad(&mut s, ADD, base(json!({"tcp_flags": "syn"})));
    assert_eq!(
        (param.as_str(), why.as_str()),
        ("protocol", "change-mss needs protocol=tcp")
    );
    let (param, why) = bad(&mut s, ADD, base(json!({"protocol": "tcp"})));
    assert_eq!(param, "tcp_flags");
    assert!(why.contains("only a SYN carries the MSS option"), "{why}");
    let (param, _) = bad(
        &mut s,
        ADD,
        base(json!({"protocol": "tcp", "tcp_flags": "!syn"})),
    );
    assert_eq!(param, "tcp_flags");
    let (param, why) = bad(
        &mut s,
        ADD,
        base(json!({"protocol": "udp", "tcp_flags": "syn"})),
    );
    assert_eq!(param, "protocol", "{why}");
    // tcp-flags alone needs TCP too, whatever the action.
    let (param, why) = bad(
        &mut s,
        ADD,
        json!({"action": "accept", "protocol": "udp", "tcp_flags": "syn"}),
    );
    assert_eq!(
        (param.as_str(), why.as_str()),
        ("tcp_flags", "needs protocol=tcp")
    );
    // rt mtu needs the route: not before routing.
    let (param, why) = bad(
        &mut s,
        ADD,
        json!({"chain": "prerouting", "action": "change-mss", "new_mss": "clamp-to-pmtu",
               "protocol": "tcp", "tcp_flags": "syn"}),
    );
    assert_eq!(param, "action");
    assert!(why.contains("forward or output or postrouting"), "{why}");
    let (param, why) = bad(&mut s, ADD, base(json!({"new_mss": "40"})));
    assert_eq!(param, "new_mss");
    assert!(why.contains("88..65535"), "{why}");
    let (param, _) = bad(
        &mut s,
        ADD,
        json!({"chain": "forward", "action": "change-mss", "protocol": "tcp", "tcp_flags": "syn"}),
    );
    assert_eq!(param, "new_mss");
    // Only the mangle has it: filter does not even take new_mss.
    let e = s
        .execute(
            "ip.firewall.filter.add",
            &json!({"action": "change-mss", "new_mss": "1400", "protocol": "tcp", "tcp_flags": "syn"}),
        )
        .unwrap_err();
    assert!(
        matches!(&e, EngineError::UnknownParam { param, .. } if param == "new_mss"),
        "{e:?}"
    );
    let (param, _) = bad(&mut s, ADD, json!({"action": "accept", "new_mss": "1400"}));
    assert_eq!(param, "new_mss");
    assert!(s.store().running().ip.firewall.mangle.is_empty());
}

#[test]
fn rollback_takes_the_rule_away() {
    let mut s = Session::virtual_lab();
    let rev = s.store().current_revision();
    ok(
        &mut s,
        ADD,
        json!({"chain": "postrouting", "action": "change-mss", "new_mss": "1360",
               "protocol": "tcp", "tcp_flags": "syn,!ack"}),
    );
    assert_eq!(s.store().running().ip.firewall.mangle.len(), 1);
    ok(&mut s, "config.rollback", json!({"revision": rev}));
    assert!(s.store().running().ip.firewall.mangle.is_empty());
}

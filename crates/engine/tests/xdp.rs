//! G2.5a — IP › Firewall › XDP: a block list that would drop the
//! management connection in the driver is a lockout, like a firewall rule.
#![allow(clippy::unwrap_used, clippy::panic)]

use corerouter_engine::{Caller, EngineError, Link, Principal, Session};
use serde_json::{Value, json};

fn from_wan() -> Caller {
    Caller::new(9, "tls 198.51.100.7:50123")
        .with_principal(Principal::Local)
        .with_link(Link {
            peer: "198.51.100.7:50123".parse().unwrap(),
            local: "203.0.113.1:8729".parse().unwrap(),
        })
}

fn ok(s: &mut Session, who: &Caller, id: &str, p: Value) -> Value {
    s.execute_as(who, id, &p)
        .unwrap_or_else(|e| panic!("{id} {p}: {e}"))
}

#[test]
fn blocking_the_operator_in_xdp_is_a_lockout() {
    let mut s = Session::virtual_lab();
    let lab = Caller::new(1, "lab").with_principal(Principal::Local);
    ok(
        &mut s,
        &lab,
        "ip.address.add",
        json!({"address": "203.0.113.1/24", "interface": "ether1"}),
    );
    ok(
        &mut s,
        &lab,
        "ip.firewall.address-list.add",
        json!({"list": "attackers", "address": "198.51.100.0/24"}),
    );
    ok(
        &mut s,
        &lab,
        "ip.firewall.xdp.interface.add",
        json!({"interface": "ether1"}),
    );
    let wan = from_wan();
    match s.execute_as(
        &wan,
        "ip.firewall.xdp.set",
        &json!({"block_lists": "attackers"}),
    ) {
        Err(e @ EngineError::Lockout(_)) => {
            let msg = e.to_string();
            assert!(msg.contains("XDP filter would drop 198.51.100.7"), "{msg}");
            assert!(
                msg.contains("'attackers'") && msg.contains("allow list"),
                "{msg}"
            );
        }
        other => panic!("expected a lockout, got {other:?}"),
    }
    assert!(
        s.store().candidate().ip.xdp.filter.block_lists.is_empty(),
        "rolled back"
    );
    // With the operator's host in an allow list, the block goes in.
    ok(
        &mut s,
        &lab,
        "ip.firewall.address-list.add",
        json!({"list": "noc", "address": "198.51.100.7"}),
    );
    ok(
        &mut s,
        &wan,
        "ip.firewall.xdp.set",
        json!({"block_lists": "attackers", "allow_lists": "noc"}),
    );
    // Taking the allow list away is the lockout now; force says yes.
    let err = s
        .execute_as(&wan, "ip.firewall.xdp.set", &json!({"allow_lists": ""}))
        .unwrap_err();
    assert!(matches!(err, EngineError::Lockout(_)), "{err}");
    ok(
        &mut s,
        &wan,
        "ip.firewall.xdp.set",
        json!({"allow_lists": "", "force": true}),
    );
}

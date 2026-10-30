//! G1.3g: a firewall the kernel refuses at boot loses only the refused
//! rule, found by checks that load nothing; the reduced firewall goes in
//! once, and only if it keeps management reachable (else the whole
//! firewall stays out, saying why).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::sync::{Arc, Mutex};

use corerouter_engine::auth::whoami;
use corerouter_engine::boot_apply::BootEnv;
use corerouter_engine::{MemoryStorage, Principal, Session};
use corerouter_hal::{Hal, HalError, LinkInfo, LinkState, RefusedRule, VirtualHal};
use corerouter_model::firewall::FirewallRule;
use corerouter_model::{Config, ItemId};
use serde_json::{Value, json};

/// A rule with this comment is one the kernel refuses.
const BAD: &str = "kernel refuses";
const MGMT: u16 = 8729;

#[derive(Default)]
struct Seen {
    /// What the data plane holds.
    applied: Config,
    /// Every config the data plane took, in order.
    took: Vec<Config>,
    checks: usize,
}

/// A kernel that refuses rules commented [`BAD`]; its check names the
/// first (or, `anonymous`, refuses without naming any, as a backend that
/// cannot tell).
struct Picky {
    inner: VirtualHal,
    anonymous: bool,
    seen: Arc<Mutex<Seen>>,
}

fn bad_rules(c: &Config) -> Vec<ItemId> {
    c.ip.firewall
        .filter
        .iter()
        .chain(c.ip.firewall.nat.iter())
        .filter(|r| !r.disabled && r.comment == BAD)
        .map(|r| r.id)
        .collect()
}

impl Hal for Picky {
    fn describe(&self) -> String {
        "picky lab".into()
    }
    fn discover_links(&mut self) -> Result<Vec<LinkInfo>, HalError> {
        self.inner.discover_links()
    }
    fn apply(&mut self, from: &Config, to: &Config) -> Result<(), HalError> {
        if !bad_rules(to).is_empty() {
            return Err(HalError::Rejected(
                "nftables: Operation not supported".into(),
            ));
        }
        self.inner.apply(from, to)?;
        let mut seen = self.seen.lock().unwrap();
        seen.applied = to.clone();
        seen.took.push(to.clone());
        Ok(())
    }
    fn check_firewall(&mut self, to: &Config) -> Result<Vec<RefusedRule>, HalError> {
        self.seen.lock().unwrap().checks += 1;
        match bad_rules(to).first() {
            None => Ok(Vec::new()),
            Some(_) if self.anonymous => Err(HalError::Rejected("refused, no rule named".into())),
            Some(id) => Ok(vec![RefusedRule {
                id: *id,
                reason: "Operation not supported (os error 95)".into(),
            }]),
        }
    }
    fn poll(&mut self) -> Vec<LinkState> {
        self.inner.poll()
    }
    fn now_unix(&self) -> Option<u64> {
        None
    }
}

struct Booted {
    s: Session,
    seen: Arc<Mutex<Seen>>,
}

impl Booted {
    fn applied<T>(&self, f: impl Fn(&Config) -> T) -> T {
        f(&self.seen.lock().unwrap().applied)
    }
    fn live_filter(&self) -> Vec<String> {
        self.applied(|c| {
            c.ip.firewall
                .filter
                .iter()
                .filter(|r| !r.disabled)
                .map(|r| r.id.to_string())
                .collect()
        })
    }
    fn failed(&self) -> Vec<Value> {
        let st = self.s.inspect(None).unwrap();
        st["storage"]["boot_apply_failed"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }
    fn check(&mut self, key: &str) -> Option<Value> {
        let v = self.s.execute("system.health.check", &json!({})).unwrap();
        v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["key"] == key)
            .cloned()
    }
    fn rule(&mut self, id: &str) -> Value {
        let rows = self
            .s
            .execute("ip.firewall.filter.list", &json!({}))
            .unwrap();
        rows.as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .cloned()
            .unwrap()
    }
}

/// Saved: the management address and `rules` (filter: chain, action,
/// extra matchers; refused when `bad`), booted on [`Picky`].
fn boot(rules: &[(&str, &str, Value, bool)], anonymous: bool) -> (Booted, Vec<String>) {
    let storage = MemoryStorage::default();
    let mut s = Session::with_storage(Box::new(VirtualHal::default()), Box::new(storage.clone()));
    s.execute(
        "ip.address.add",
        &json!({"address": "10.0.0.1/24", "interface": "ether1"}),
    )
    .unwrap();
    let mut ids = Vec::new();
    for (chain, action, extra, bad) in rules {
        let mut p = json!({"chain": chain, "action": action});
        if let (Some(o), Some(e)) = (p.as_object_mut(), extra.as_object()) {
            o.extend(e.clone());
        }
        if *bad {
            p["comment"] = json!(BAD);
        }
        let v = s.execute("ip.firewall.filter.add", &p).unwrap();
        ids.push(v["id"].as_str().unwrap().to_owned());
    }
    drop(s);
    let seen = Arc::new(Mutex::new(Seen::default()));
    let hal = Picky {
        inner: VirtualHal::default(),
        anonymous,
        seen: Arc::clone(&seen),
    };
    let env = BootEnv {
        management_ports: vec![MGMT],
    };
    let s = Session::with_storage_env(Box::new(hal), Box::new(storage), env);
    (Booted { s, seen }, ids)
}

fn mgmt_accept() -> (&'static str, &'static str, Value, bool) {
    (
        "input",
        "accept",
        json!({"protocol": "tcp", "dst_port": MGMT.to_string()}),
        false,
    )
}

/// A firewall with one rule the kernel refuses: only that rule is out,
/// invalid with the kernel's reason; the rest, management included, is in.
#[test]
fn only_the_refused_rule_stays_out() {
    let (mut b, ids) = boot(
        &[
            mgmt_accept(),
            ("forward", "accept", json!({"protocol": "udp"}), true),
            ("input", "drop", json!({}), false),
            ("forward", "drop", json!({"protocol": "tcp"}), false),
        ],
        false,
    );
    let bad = &ids[1];
    let mut want: Vec<String> = ids.clone();
    want.remove(1);
    assert_eq!(b.live_filter(), want, "every rule but the refused one");
    let failed = b.failed();
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(failed[0]["section"], "firewall");
    assert_eq!(failed[0]["rule"], bad.as_str());
    // Flag I with the reason, in the rule list.
    let row = b.rule(bad);
    assert_eq!(row["flags"], "I");
    assert_eq!(row["invalid"], true);
    assert!(
        row["reason"]
            .as_str()
            .unwrap()
            .contains("Operation not supported"),
        "{row}"
    );
    let c = b.check("boot.apply").unwrap();
    assert_eq!(c["value"], format!("firewall {bad}"));
    let me = whoami(&b.s, &Principal::Local, "test");
    assert_eq!(me["boot_errors"][0]["rule"], bad.as_str());
    // Nothing partial ever reached the data plane: the core, then the
    // firewall without the rule, once.
    let seen = b.seen.lock().unwrap();
    let firewalls: Vec<usize> = seen
        .took
        .iter()
        .map(|c| c.ip.firewall.filter.iter().filter(|r| !r.disabled).count())
        .collect();
    assert!(
        firewalls.iter().all(|n| *n == 0 || *n == 3),
        "{firewalls:?}"
    );
    assert_eq!(seen.checks, 2, "one check finds it, one confirms the rest");
}

/// The case the operator asked about: the refused rule is the one that
/// lets management in, and the firewall ends in a drop. Without it the
/// firewall would lock management out, so the firewall stays out whole
/// (as G1.3e) and the router stays reachable, saying why.
#[test]
fn the_refused_management_accept_keeps_the_router_reachable() {
    let (b, ids) = boot(
        &[
            (
                "input",
                "accept",
                json!({"protocol": "tcp", "dst_port": MGMT.to_string()}),
                true,
            ),
            ("input", "drop", json!({}), false),
        ],
        false,
    );
    assert_eq!(
        b.applied(|c| c.ip.addresses.len()),
        1,
        "management address in"
    );
    assert!(
        b.live_filter().is_empty(),
        "no drop without the accept: {:?}",
        b.live_filter()
    );
    let failed = b.failed();
    assert_eq!(failed.len(), 1, "{failed:?}");
    assert_eq!(failed[0]["section"], "firewall");
    assert!(failed[0].get("rule").is_none(), "{failed:?}");
    let why = failed[0]["error"].as_str().unwrap();
    assert!(why.contains(&format!("rule {}", ids[0])), "{why}");
    assert!(why.contains("would cut management"), "{why}");
    assert!(why.contains("whole firewall stays out"), "{why}");
    // A new login to the management port still gets in.
    let applied = b.applied(Clone::clone);
    let p = corerouter_firewall::eval::Packet {
        src: "10.0.0.9".parse().unwrap(),
        dst: "10.0.0.1".parse().unwrap(),
        protocol: corerouter_model::firewall::Protocol::TCP,
        src_port: Some(40_000),
        dst_port: Some(MGMT),
        icmp: None,
        in_interface: Some("ether1".into()),
        out_interface: None,
        state: corerouter_model::firewall::ConnState::New,
        nat: None,
    };
    let out = corerouter_firewall::eval::walk(
        &applied,
        &[],
        corerouter_model::firewall::Table::Filter,
        "input",
        &p,
    );
    assert!(!out.verdict.blocks(), "{out:?}");
}

/// The refused accept only for another port: management is not at stake,
/// so only it stays out.
#[test]
fn a_refused_accept_that_management_does_not_need_stays_out_alone() {
    let (b, ids) = boot(
        &[
            mgmt_accept(),
            (
                "input",
                "accept",
                json!({"protocol": "udp", "dst_port": "53"}),
                true,
            ),
            ("input", "drop", json!({}), false),
        ],
        false,
    );
    assert_eq!(b.live_filter(), [ids[0].clone(), ids[2].clone()]);
    assert_eq!(b.failed()[0]["rule"], ids[1].as_str());
}

/// Two refused rules: the kernel names only the first (the ones after it
/// may be refused only because of it), so out one, check again.
#[test]
fn two_refused_rules_both_out_one_check_each() {
    let (b, ids) = boot(
        &[
            mgmt_accept(),
            ("forward", "accept", json!({"protocol": "udp"}), true),
            ("forward", "drop", json!({"protocol": "tcp"}), false),
            ("forward", "accept", json!({"protocol": "icmp"}), true),
        ],
        false,
    );
    assert_eq!(b.live_filter(), [ids[0].clone(), ids[2].clone()]);
    let rules: Vec<Value> = b.failed().iter().map(|f| f["rule"].clone()).collect();
    assert_eq!(rules, [json!(ids[1]), json!(ids[3])]);
    assert_eq!(b.seen.lock().unwrap().checks, 3);
}

/// A backend whose refusal names no rule: found by halving, with checks
/// only; nothing partial reaches the data plane.
#[test]
fn bisection_when_the_refusal_names_no_rule() {
    let mut rules = vec![mgmt_accept()];
    for i in 0..30 {
        rules.push((
            "forward",
            "drop",
            json!({"dst_address": format!("10.9.{i}.0/24")}),
            i == 17,
        ));
    }
    let (b, ids) = boot(&rules, true);
    let bad = ids[18].clone();
    assert_eq!(b.failed()[0]["rule"], bad.as_str());
    assert_eq!(b.live_filter().len(), 30);
    let seen = b.seen.lock().unwrap();
    assert!(
        seen.took
            .iter()
            .all(|c| c.ip.firewall.filter.iter().filter(|r| !r.disabled).count() % 30 == 0),
        "only the core and the reduced firewall went in"
    );
    // ~log₂ 31 halvings + the first check + the confirmation.
    assert!(seen.checks <= 9, "{} checks", seen.checks);
}

/// A commit that changes another rule works with the refused one still
/// out; a commit that removes the refused rule clears the boot error.
#[test]
fn commits_with_a_rule_out() {
    let (mut b, ids) = boot(
        &[
            mgmt_accept(),
            ("forward", "accept", json!({"protocol": "udp"}), true),
        ],
        false,
    );
    b.s.execute(
        "ip.firewall.filter.add",
        &json!({"chain": "forward", "action": "drop"}),
    )
    .unwrap();
    assert_eq!(b.live_filter().len(), 2, "the new rule went in");
    assert_eq!(b.failed()[0]["rule"], ids[1].as_str(), "still out");
    assert_eq!(b.rule(&ids[1])["flags"], "I");
    b.s.execute("ip.firewall.filter.remove", &json!({"id": ids[1]}))
        .unwrap();
    assert!(b.failed().is_empty());
    assert!(b.check("boot.apply").is_none());
}

/// Rules out only: finding them again costs the kernel a validation per
/// rule, so the retry waits up to 10 minutes, not 1.
#[test]
fn retries_of_single_rules_back_off_to_ten_minutes() {
    let (mut b, _) = boot(
        &[
            mgmt_accept(),
            ("forward", "accept", json!({"protocol": "udp"}), true),
        ],
        false,
    );
    let checks = b.seen.lock().unwrap().checks;
    for t in 0..1200 {
        b.s.tick(10_000 + t);
    }
    // Retries at +0, +1, +3, +7, +15, +31, +63, +127, +255, +511, +1023.
    let retries = (b.seen.lock().unwrap().checks - checks) / 2;
    assert_eq!(retries, 11);
}

/// The rules of a config, for a sanity check of the helpers above.
#[test]
fn the_lab_refuses_only_bad_rules() {
    let mut c = Config::default();
    let r: FirewallRule = serde_json::from_value(json!({
        "id": "*1", "chain": "input", "action": {"type": "accept"}, "comment": BAD
    }))
    .unwrap();
    c.ip.firewall.filter.push(r);
    assert_eq!(bad_rules(&c), [ItemId(1)]);
}

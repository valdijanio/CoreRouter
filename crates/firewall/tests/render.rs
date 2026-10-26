//! Golden tests of the nftables render and the validator's verdicts.
//!
//! `UPDATE_GOLDEN=1 cargo test -p corerouter-firewall` rewrites the files in
//! `tests/golden/` (review the diff). `hal-linux`'s netns test loads the
//! same ruleset into a real kernel.
// Shared helpers are not `#[test]` fns, so clippy's in-tests allowances skip them.
#![allow(clippy::unwrap_used, clippy::panic)]

use corerouter_firewall::{render, rule_issues, script, validate};
use corerouter_model::Config;
use corerouter_model::firewall::{Action, DynamicAddress, FirewallRule, Table};

use corerouter_firewall::sample::{self, sample};
use corerouter_model::firewall::Matchers;

fn rule(id: u32, chain: &str, m: Matchers, action: Action) -> FirewallRule {
    sample::rule(id, chain, m, action).unwrap()
}

fn m(pairs: &[(&str, &str)]) -> Matchers {
    sample::m(pairs).unwrap()
}

fn act(json: &str) -> Action {
    sample::act(json).unwrap()
}

fn golden(name: &str, actual: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e} (run with UPDATE_GOLDEN=1)", path.display()));
    assert_eq!(
        actual, expected,
        "render changed; if intended, run UPDATE_GOLDEN=1 cargo test -p corerouter-firewall"
    );
}

#[test]
fn sample_is_valid() {
    assert_eq!(
        sample().ip.firewall.filter.len(),
        15,
        "every fixture value parsed"
    );
    let issues = validate(&sample());
    assert!(issues.is_empty(), "{issues:#?}");
}

#[test]
fn golden_full_ruleset() {
    let dynamic = [DynamicAddress {
        list: "blocked".parse().unwrap(),
        address: "192.0.2.99".parse().unwrap(),
        timeout_secs: 600,
        added_by_rule: false,
    }];
    golden("full.nft", &script(&sample(), &dynamic));
}

#[test]
fn golden_empty_config_removes_the_table() {
    assert_eq!(render(&Config::default(), &[]), None);
    golden("empty.nft", &script(&Config::default(), &[]));
}

#[test]
fn only_our_table_is_touched() {
    let text = script(&sample(), &[]);
    for line in text.lines() {
        let l = line.trim_start();
        if l.starts_with("table") || l.starts_with("delete") {
            assert!(l.contains("inet corerouter"), "{l}");
        }
    }
}

#[test]
fn validator_refuses_what_the_kernel_or_routeros_would() {
    let cfg = sample();
    let check = |table: Table, r: FirewallRule, field: &str| {
        let issues = rule_issues(&cfg, table, &r);
        assert!(
            issues.iter().any(|(f, _)| *f == field),
            "{field} not flagged: {issues:?}"
        );
    };
    // Masquerade outside srcnat, dst-nat outside dstnat, drop in nat.
    check(
        Table::Nat,
        rule(50, "dstnat", m(&[]), act(r#"{"type":"masquerade"}"#)),
        "action",
    );
    check(
        Table::Nat,
        rule(
            50,
            "srcnat",
            m(&[]),
            act(r#"{"type":"dst-nat","to_addresses":"10.0.0.1"}"#),
        ),
        "action",
    );
    check(
        Table::Nat,
        rule(50, "srcnat", m(&[]), Action::Drop),
        "action",
    );
    check(
        Table::Filter,
        rule(50, "input", m(&[]), act(r#"{"type":"masquerade"}"#)),
        "action",
    );
    // Ports without tcp/udp; icmp options without icmp.
    check(
        Table::Filter,
        rule(50, "input", m(&[("dst_port", "22")]), Action::Accept),
        "dst_port",
    );
    check(
        Table::Filter,
        rule(
            50,
            "input",
            m(&[("protocol", "!tcp"), ("dst_port", "22")]),
            Action::Accept,
        ),
        "dst_port",
    );
    check(
        Table::Filter,
        rule(50, "input", m(&[("icmp_options", "8")]), Action::Accept),
        "icmp_options",
    );
    // Families that exclude each other.
    check(
        Table::Filter,
        rule(
            50,
            "input",
            m(&[("src_address", "10.0.0.1"), ("dst_address", "::1")]),
            Action::Accept,
        ),
        "dst_address",
    );
    check(
        Table::Filter,
        rule(
            50,
            "input",
            m(&[("protocol", "icmpv6"), ("src_address", "10.0.0.1")]),
            Action::Accept,
        ),
        "protocol",
    );
    // Interfaces that do not exist at that point of the path.
    check(
        Table::Filter,
        rule(
            50,
            "output",
            m(&[("in_interface", "ether1")]),
            Action::Accept,
        ),
        "in_interface",
    );
    check(
        Table::Filter,
        rule(
            50,
            "input",
            m(&[("out_interface", "ether1")]),
            Action::Accept,
        ),
        "out_interface",
    );
    check(
        Table::Filter,
        rule(
            50,
            "input",
            m(&[("in_interface_list", "DMZ")]),
            Action::Accept,
        ),
        "in_interface_list",
    );
    // tcp-reset without tcp; log prefix with a quote; jump to a built-in.
    check(
        Table::Filter,
        rule(
            50,
            "input",
            m(&[]),
            act(r#"{"type":"reject","reject_with":"tcp-reset"}"#),
        ),
        "reject_with",
    );
    check(
        Table::Filter,
        rule(
            50,
            "input",
            m(&[]),
            act(r#"{"type":"log","log_prefix":"a\"b"}"#),
        ),
        "log_prefix",
    );
    check(
        Table::Filter,
        rule(
            50,
            "input",
            m(&[]),
            act(r#"{"type":"jump","jump_target":"forward"}"#),
        ),
        "jump_target",
    );
    // mark-routing outside prerouting/output; to-ports without a protocol.
    check(
        Table::Mangle,
        rule(
            50,
            "forward",
            m(&[]),
            act(r#"{"type":"mark-routing","new_routing_mark":"x"}"#),
        ),
        "action",
    );
    check(
        Table::Nat,
        rule(
            50,
            "dstnat",
            m(&[]),
            act(r#"{"type":"dst-nat","to_addresses":"10.0.0.1","to_ports":"80"}"#),
        ),
        "to_ports",
    );
    // A src-nat in a custom chain reached from dstnat.
    let mut cfg2 = cfg.clone();
    cfg2.ip.firewall.nat.push(rule(
        60,
        "dstnat",
        m(&[]),
        act(r#"{"type":"jump","jump_target":"mine"}"#),
    ));
    let bad = rule(
        61,
        "mine",
        m(&[]),
        act(r#"{"type":"src-nat","to_addresses":"10.0.0.1"}"#),
    );
    assert!(
        rule_issues(&cfg2, Table::Nat, &bad)
            .iter()
            .any(|(f, _)| *f == "action")
    );
}

#[test]
fn jump_loops_are_refused() {
    let mut cfg = Config::default();
    cfg.ip.firewall.filter = corerouter_model::cow_list::CowList::from(vec![
        rule(
            1,
            "input",
            m(&[]),
            act(r#"{"type":"jump","jump_target":"a"}"#),
        ),
        rule(2, "a", m(&[]), act(r#"{"type":"jump","jump_target":"b"}"#)),
        rule(3, "b", m(&[]), act(r#"{"type":"jump","jump_target":"a"}"#)),
    ]);
    let issues = validate(&cfg);
    assert!(
        issues.iter().any(|i| i.message.contains("loop")),
        "{issues:?}"
    );
}

#[test]
fn families_split_only_for_address_lists() {
    let cfg = sample();
    let text = render(&cfg, &[]).unwrap();
    let tagged = |id: &str| {
        text.lines()
            .filter(|l| l.contains(&format!("\"cr:{id}\"")))
            .count()
    };
    assert_eq!(
        tagged("*7"),
        2,
        "both families + address list = 2 kernel rules"
    );
    assert_eq!(
        tagged("*6"),
        4,
        "a list that rule 21 (*15) fills: static or dynamic set, per family"
    );
    assert_eq!(tagged("*15"), 2, "filling a list (rule 21) needs ip or ip6");
    assert_eq!(tagged("*2"), 1);
    assert_eq!(tagged("*9"), 0, "disabled rules are not rendered");
    assert_eq!(tagged("*1"), 0, "sections are not rendered");
}

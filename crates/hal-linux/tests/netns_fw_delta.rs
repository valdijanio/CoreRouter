//! G0.31f: a firewall commit from what the previous one loaded (no
//! kernel read) leaves the kernel exactly as loading the new config from
//! scratch would, also when someone changed nftables in between. In a
//! throwaway network namespace (no root, nothing reaches the host):
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_fw_delta
//! ```
#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::process::Command;

use corerouter_firewall::program::{Chain, Expr, FwSet};
use corerouter_firewall::sample::{act, m, rule};
use corerouter_hal_linux::{firewall, nfnl, nft, nft_read};
use corerouter_model::Config;
use corerouter_model::cow_list::CowList;
use corerouter_model::firewall::{Action, AddressListEntry, FirewallRule, Table};
use proptest::prelude::*;

const ENV: &str = "COREROUTER_NETNS_TESTS";

static KERNEL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn ready() -> bool {
    if std::env::var_os(ENV).is_none_or(|v| v != "1") {
        eprintln!("skipped: set {ENV}=1 and run inside `unshare --user --map-root-user --net`");
        return false;
    }
    let out = Command::new("ip")
        .args(["-o", "link", "show"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let names: Vec<&str> = text
        .lines()
        .filter_map(|l| l.split(':').nth(1))
        .map(str::trim)
        .collect();
    assert!(
        names == ["lo"],
        "{ENV}=1 but this namespace has {names:?}; refusing to touch it"
    );
    if !nft::available() {
        eprintln!("skipped: the `nft` program (nftables) is not installed");
        return false;
    }
    true
}

type Rules = Vec<(Vec<Expr>, Option<String>)>;

/// What the kernel holds, in an order that does not depend on how it got
/// there: chains and sets by name, each chain's rules in order.
#[derive(Debug, PartialEq, Eq)]
struct Held {
    chains: Vec<(Chain, Rules)>,
    sets: Vec<FwSet>,
}

fn held() -> Option<Held> {
    let d = nft_read::read_table(firewall::FAMILY, "corerouter", true, true).unwrap()?;
    assert!(d.rules.iter().all(|r| !r.unknown), "{:?}", d.rules);
    let mut chains: Vec<(Chain, Rules)> = d
        .chains
        .into_iter()
        .map(|c| {
            let rules = d
                .rules
                .iter()
                .filter(|r| r.rule.chain == c.name)
                .map(|r| (r.rule.exprs.clone(), r.rule.comment.clone()))
                .collect();
            (c, rules)
        })
        .collect();
    chains.sort_by(|a, b| a.0.name.cmp(&b.0.name));
    let mut sets = d.sets;
    sets.sort_by(|a, b| a.name.cmp(&b.name));
    Some(Held { chains, sets })
}

/// What loading `cfg` from scratch leaves in the kernel.
fn fresh(cfg: &Config) -> Option<Held> {
    firewall::replace(cfg).unwrap();
    held()
}

/// Rule `id` of a varied ruleset: addresses, port lists, address lists,
/// states, custom chains.
fn nth(id: u32, chain: &str, flavor: u32) -> FirewallRule {
    let src = format!("10.{}.{}.0/24", (id >> 8) & 0xff, id & 0xff);
    let list = format!("list{}", flavor % 3);
    let ports = format!("{},{}", 1000 + flavor % 5, 2000 + flavor % 7);
    let pairs: Vec<(&str, &str)> = match flavor % 6 {
        0 => vec![
            ("src_address", src.as_str()),
            ("protocol", "tcp"),
            ("dst_port", "22,80,443"),
        ],
        1 => vec![
            ("src_address_list", list.as_str()),
            ("connection_state", "new"),
        ],
        2 => vec![("protocol", "udp"), ("dst_port", ports.as_str())],
        3 => vec![
            ("in_interface", "ether1"),
            ("connection_state", "established,related"),
        ],
        4 => vec![("dst_address_list", list.as_str()), ("protocol", "icmp")],
        _ => vec![("dst_address", src.as_str())],
    };
    let a = match flavor % 3 {
        0 => r#"{"type":"accept"}"#,
        1 => r#"{"type":"drop"}"#,
        _ => r#"{"type":"passthrough"}"#,
    };
    rule(id, chain, m(&pairs).unwrap(), act(a).unwrap()).unwrap()
}

fn jump(id: u32, chain: &str, target: &str) -> FirewallRule {
    let a = format!(r#"{{"type":"jump","jump_target":"{target}"}}"#);
    rule(
        id,
        chain,
        m(&[("protocol", "tcp")]).unwrap(),
        act(&a).unwrap(),
    )
    .unwrap()
}

fn base(n: u32) -> Config {
    let mut cfg = Config::default();
    cfg.ip.firewall.address_lists.push(AddressListEntry {
        id: corerouter_model::ItemId(1),
        list: "list0".parse().unwrap(),
        address: "203.0.113.0/24".parse().unwrap(),
        disabled: false,
        comment: String::new(),
    });
    let mut filter: Vec<FirewallRule> = (1..=n)
        .map(|i| {
            let chain = ["input", "forward", "forward", "output"][(i % 4) as usize];
            nth(i, chain, i)
        })
        .collect();
    filter.push(jump(n + 1, "forward", "custom1"));
    filter.push(nth(n + 2, "custom1", 0));
    cfg.ip.firewall.filter = CowList::from(filter);
    cfg.ip.firewall.mangle = CowList::from(vec![nth(n + 3, "prerouting", 3)]);
    cfg.ip.firewall.next_rule_id = n + 3;
    cfg
}

/// One edit of the rule tables, as the engine makes them (in place, so the
/// configs share the blocks the edit did not touch).
#[derive(Debug, Clone)]
enum Op {
    Insert {
        at: usize,
        chain: usize,
        flavor: u32,
    },
    Remove {
        at: usize,
    },
    Move {
        from: usize,
        to: usize,
    },
    Toggle {
        at: usize,
    },
    Retarget {
        at: usize,
        flavor: u32,
    },
    /// A new custom chain and the jump into it.
    NewChain {
        at: usize,
        k: u32,
    },
    /// Every rule copied: nothing shared with the previous config.
    Rebuild,
    Mangle {
        flavor: u32,
    },
}

fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (any::<usize>(), 0usize..5, 0u32..60).prop_map(|(at, chain, flavor)| Op::Insert { at, chain, flavor }),
        2 => any::<usize>().prop_map(|at| Op::Remove { at }),
        1 => (any::<usize>(), any::<usize>()).prop_map(|(from, to)| Op::Move { from, to }),
        1 => any::<usize>().prop_map(|at| Op::Toggle { at }),
        2 => (any::<usize>(), 0u32..60).prop_map(|(at, flavor)| Op::Retarget { at, flavor }),
        1 => (any::<usize>(), 2u32..5).prop_map(|(at, k)| Op::NewChain { at, k }),
        1 => Just(Op::Rebuild),
        1 => (0u32..60).prop_map(|flavor| Op::Mangle { flavor }),
    ]
}

fn edit(cfg: &Config, op: &Op) -> Config {
    let mut c = cfg.clone();
    let fw = &mut c.ip.firewall;
    let len = fw.filter.len().max(1);
    match op {
        Op::Insert { at, chain, flavor } => {
            let id = fw.next_rule_id().0;
            let chain = ["input", "forward", "output", "custom1", "forward"][*chain];
            fw.filter.insert(at % (len + 1), nth(id, chain, *flavor));
        }
        Op::Remove { at } => {
            // Jumps stay (their chains keep a reason to exist).
            if fw
                .filter
                .get(at % len)
                .is_some_and(|r| !matches!(r.action, Action::Jump { .. }))
            {
                fw.filter.remove(at % len);
            }
        }
        Op::Move { from, to } => {
            fw.filter.move_item(from % len, to % len);
        }
        Op::Toggle { at } => {
            if let Some(r) = fw.filter.get_mut(at % len) {
                r.disabled = !r.disabled;
            }
        }
        Op::Retarget { at, flavor } => {
            if let Some(r) = fw.filter.get_mut(at % len)
                && !matches!(r.action, Action::Jump { .. })
            {
                *r = nth(r.id.0, r.chain.as_str(), *flavor);
            }
        }
        Op::NewChain { at, k } => {
            let target = format!("custom{k}");
            let id = fw.next_rule_id().0;
            fw.filter
                .insert(at % (len + 1), jump(id, "forward", &target));
            let id = fw.next_rule_id().0;
            fw.filter.push(nth(id, &target, *k));
        }
        Op::Rebuild => {
            fw.filter = CowList::from(fw.filter.iter().cloned().collect::<Vec<_>>());
        }
        Op::Mangle { flavor } => {
            let id = fw.next_rule_id().0;
            let chain = ["prerouting", "forward", "postrouting"][(*flavor % 3) as usize];
            fw.rules_mut(Table::Mangle).push(nth(id, chain, *flavor));
        }
    }
    c
}

/// Seed what the firewall keeps: a load, then one commit that reads the
/// kernel (the load alone does not learn the handles).
fn seeded(n: u32) -> Config {
    firewall::remove().unwrap();
    let a = base(n);
    assert!(firewall::apply(&Config::default(), &a).unwrap().replaced);
    let b = edit(&a, &Op::Toggle { at: 0 });
    let done = firewall::apply(&a, &b).unwrap();
    assert!(!done.replaced && !done.cached, "{done:?}");
    b
}

#[test]
fn a_cached_commit_reads_back_as_a_fresh_load() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let mut cfg = seeded(200);
    let ops = [
        Op::Insert {
            at: 50,
            chain: 1,
            flavor: 2,
        },
        Op::Insert {
            at: 0,
            chain: 0,
            flavor: 7,
        },
        Op::Remove { at: 120 },
        Op::Move { from: 10, to: 150 },
        Op::Retarget { at: 33, flavor: 11 },
        Op::NewChain { at: 5, k: 3 },
        Op::Mangle { flavor: 4 },
        Op::Toggle { at: 7 },
        Op::Rebuild,
        Op::Insert {
            at: 100,
            chain: 3,
            flavor: 1,
        },
    ];
    for op in &ops {
        let next = edit(&cfg, op);
        let done = firewall::apply(&cfg, &next).unwrap();
        assert!(done.cached && !done.replaced, "{op:?}: {done:?}");
        cfg = next;
    }
    let delta = held().unwrap();
    assert_eq!(Some(delta), fresh(&cfg));
}

#[test]
fn a_rule_that_did_not_change_keeps_its_handle() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let a = seeded(100);
    let handles = || {
        nft_read::read_table(firewall::FAMILY, "corerouter", false, false)
            .unwrap()
            .unwrap()
            .rules
            .into_iter()
            .map(|r| (r.rule.comment, r.handle))
            .collect::<Vec<_>>()
    };
    let before = handles();
    let b = edit(&a, &Op::Retarget { at: 40, flavor: 13 });
    let changed = b.ip.firewall.filter.get(40).map(|r| r.id).unwrap();
    let done = firewall::apply(&a, &b).unwrap();
    assert!(done.cached, "{done:?}");
    let after = handles();
    let tag = corerouter_firewall::nft::rule_tag(changed);
    for (c, h) in &before {
        let kept = after.contains(&(c.clone(), *h));
        assert_eq!(kept, c.as_deref() != Some(tag.as_str()), "{c:?}");
    }
    // A comment is not in the kernel: the rule keeps its handle too.
    let mut c = b.clone();
    if let Some(r) = c.ip.firewall.filter.get_mut(3) {
        r.comment = "edited".into();
    }
    let done = firewall::apply(&b, &c).unwrap();
    assert!(done.cached, "{done:?}");
    assert_eq!((done.rules_added, done.rules_removed), (0, 0), "{done:?}");
}

/// Someone changes nftables between two commits: the next one notices,
/// reads the kernel, and still ends where a fresh load would.
#[test]
fn drift_falls_back_to_reading_the_kernel() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let nft_cmd = |args: &str| {
        let ok = Command::new("nft")
            .args(args.split(' '))
            .status()
            .unwrap()
            .success();
        assert!(ok, "nft {args}");
    };
    let drifts: [&dyn Fn(); 5] = [
        // A rule added by hand to our chain.
        &|| nft_cmd("add rule inet corerouter filter_forward counter"),
        // Our chain emptied.
        &|| nft_cmd("flush chain inet corerouter filter_forward"),
        // Our table gone.
        &|| nft_cmd("delete table inet corerouter"),
        // Another program's table: ours is intact, but we cannot know.
        &|| nft_cmd("add table inet someone_else"),
        // Our own process writes the table outside the commit.
        &|| {
            let t = corerouter_firewall::nft::program(&base(3), &[]).unwrap();
            nfnl::apply(nfnl::replace(&t, 1), "test").unwrap();
        },
    ];
    for (i, drift) in drifts.iter().enumerate() {
        let a = seeded(100);
        drift();
        let b = edit(
            &a,
            &Op::Insert {
                at: 20,
                chain: 1,
                flavor: 4,
            },
        );
        let done = firewall::apply(&a, &b).unwrap();
        assert!(!done.cached, "drift {i}: {done:?}");
        let got = held();
        assert_eq!(got, fresh(&b), "drift {i}");
        // The commit after reads the kernel no more.
        let a = seeded(100);
        let b = edit(&a, &Op::Remove { at: 5 });
        assert!(firewall::apply(&a, &b).unwrap().cached, "drift {i}");
    }
    nft_cmd("delete table inet someone_else");
    firewall::remove().unwrap();
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(16).min(64),
        ..ProptestConfig::default()
    })]

    /// Random edits, each committed from what the previous commit loaded,
    /// read back as the last config loaded from scratch.
    #[test]
    fn random_edits_read_back_as_a_fresh_load(ops in proptest::collection::vec(arb_op(), 1..12)) {
        if !ready() {
            return Ok(());
        }
        let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
        let mut cfg = seeded(40);
        for op in &ops {
            let next = edit(&cfg, op);
            let done = firewall::apply(&cfg, &next).unwrap();
            prop_assert!(done.cached, "{:?}: {:?}", op, done);
            cfg = next;
        }
        let delta = held();
        prop_assert_eq!(delta, fresh(&cfg));
    }
}

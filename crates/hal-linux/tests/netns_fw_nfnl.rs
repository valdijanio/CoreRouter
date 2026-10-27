//! G2.8: the firewall's table over nfnetlink against a real kernel, in a
//! throwaway network namespace (no root, nothing reaches the host):
//!
//! ```sh
//! COREROUTER_NETNS_TESTS=1 unshare --user --map-root-user --net -- \
//!     cargo test -p corerouter-hal-linux --test netns_fw_nfnl
//! ```
//!
//! - the same config loaded by `nft -f` (our text) and by our encoder
//!   reads back identical, object by object (`nft_read`) and as `nft list`
//!   prints it;
//! - a commit sends only the difference: rules that did not change keep
//!   their kernel handle (and so their counters);
//! - dynamic entries go in one batch, merge with what the set holds, and
//!   survive a table replace;
//! - random rules: render → nfnetlink → read back → equal (and equal to
//!   what `nft` loads from the text).
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

use corerouter_firewall::program::{Chain, Expr, FwSet};
use corerouter_firewall::sample::{act, m, rule, sample};
use corerouter_hal_linux::{firewall, nfnl, nft, nft_read};
use corerouter_model::Config;
use corerouter_model::cow_list::CowList;
use corerouter_model::firewall::{DynamicAddress, FirewallRule};
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

/// What the kernel holds, comparable across loads (no handles).
#[derive(Debug, PartialEq, Eq)]
struct Held {
    chains: Vec<Chain>,
    sets: Vec<FwSet>,
    rules: Vec<(String, Vec<Expr>, Option<String>)>,
}

fn held() -> Option<Held> {
    let d = nft_read::read_table(firewall::FAMILY, "corerouter", true, true).unwrap()?;
    assert!(d.rules.iter().all(|r| !r.unknown), "{:?}", d.rules);
    Some(Held {
        chains: d.chains,
        sets: d.sets,
        rules: d
            .rules
            .into_iter()
            .map(|r| (r.rule.chain, r.rule.exprs, r.rule.comment))
            .collect(),
    })
}

/// `nft list table inet corerouter`, without the ticking `expires …`.
fn listing() -> String {
    let out = Command::new("nft")
        .args(["list", "table", "inet", "corerouter"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.split(" expires ")
        .enumerate()
        .map(|(i, part)| {
            if i == 0 {
                part.to_owned()
            } else {
                part.trim_start_matches(|c: char| c.is_ascii_alphanumeric())
                    .to_owned()
            }
        })
        .collect()
}

/// Load `cfg` with `nft -f` (our text) and with our encoder; both must
/// read back the same. Returns what the kernel held.
fn same_both_ways(cfg: &Config, dynamic: &[DynamicAddress]) -> Held {
    firewall::remove().unwrap();
    nft::run(&corerouter_firewall::script(cfg, dynamic)).unwrap();
    let by_nft = held().expect("nft loaded the table");
    let text_nft = listing();
    firewall::remove().unwrap();
    let t = corerouter_firewall::nft::program(cfg, dynamic).unwrap();
    nfnl::apply(nfnl::replace(&t, 1), "test").unwrap();
    let ours = held().expect("we loaded the table");
    let text_ours = listing();
    assert_eq!(ours.chains, by_nft.chains);
    assert_eq!(ours.sets, by_nft.sets);
    for (i, (a, b)) in ours.rules.iter().zip(&by_nft.rules).enumerate() {
        assert_eq!(a, b, "rule {i}");
    }
    assert_eq!(ours, by_nft);
    assert_eq!(text_ours, text_nft);
    // And it is exactly the program we sent.
    let sent: Vec<_> = t
        .rules
        .iter()
        .map(|r| (r.chain.clone(), r.exprs.clone(), r.comment.clone()))
        .collect();
    for (i, (a, b)) in ours.rules.iter().zip(&sent).enumerate() {
        assert_eq!(a, b, "rule {i} as sent");
    }
    assert_eq!(ours.rules, sent);
    assert_eq!(ours.chains, t.chains);
    assert_eq!(ours.sets, t.fw_sets);
    ours
}

fn notice_config() -> Config {
    use corerouter_model::ItemId;
    use corerouter_model::subscriber_notice::{GardenEntry, Mode, Profile};
    let mut c = sample();
    let sn = &mut c.ip.subscriber_notice;
    sn.profiles.push(Profile::new(
        ItemId(1),
        "atraso".parse().unwrap(),
        Mode::Block,
        "bloqueados".parse().unwrap(),
    ));
    sn.profiles.push(Profile::new(
        ItemId(2),
        "aviso".parse().unwrap(),
        Mode::Notice,
        "aviso".parse().unwrap(),
    ));
    sn.walled_garden.push(GardenEntry {
        id: ItemId(3),
        dst_host: String::new(),
        dst_address: Some("203.0.113.0/24".parse().unwrap()),
        disabled: false,
        comment: String::new(),
    });
    c
}

#[test]
fn nft_and_netlink_load_the_same_table() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    let dynamic = [DynamicAddress {
        list: "blocked".parse().unwrap(),
        address: "192.0.2.99".parse().unwrap(),
        timeout_secs: 600,
        added_by_rule: false,
    }];
    let h = same_both_ways(&sample(), &dynamic);
    assert_eq!(h.rules.len(), 31);
    // Subscriber notices (fib, redirect, an l4proto set, reject).
    let mut c = notice_config();
    same_both_ways(&c, &[]);
    c.ip.subscriber_notice.settings.portal_address = Some("10.0.0.1".parse().unwrap());
    same_both_ways(&c, &[]);
    firewall::remove().unwrap();
}

/// Rule ids and their kernel handles, in order.
fn handles() -> Vec<(Option<String>, u64)> {
    nft_read::read_table(firewall::FAMILY, "corerouter", false, false)
        .unwrap()
        .unwrap()
        .rules
        .into_iter()
        .map(|r| (r.rule.comment, r.handle))
        .collect()
}

#[test]
fn commits_send_only_the_difference() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    firewall::remove().unwrap();
    let a = sample();
    let first = firewall::apply(&Config::default(), &a).unwrap();
    assert!(first.replaced);
    let before = handles();

    // One rule changed, one inserted in the middle, one removed.
    let mut b = a.clone();
    let mut list: Vec<FirewallRule> = b.ip.firewall.filter.iter().cloned().collect();
    list.retain(|r| r.id.0 != 3);
    if let Some(r) = list.iter_mut().find(|r| r.id.0 == 5) {
        r.matchers = m(&[("in_interface_list", "WAN")]).unwrap();
    }
    let pos = list.iter().position(|r| r.id.0 == 7).unwrap();
    list.insert(
        pos,
        rule(
            40,
            "input",
            m(&[("protocol", "udp"), ("dst_port", "53")]).unwrap(),
            act(r#"{"type":"accept"}"#).unwrap(),
        )
        .unwrap(),
    );
    b.ip.firewall.filter = CowList::from(list);
    // A new address-list entry: one element pair, no rule touched.
    b.ip.firewall
        .address_lists
        .push(corerouter_model::firewall::AddressListEntry {
            id: corerouter_model::ItemId(50),
            list: "mgmt".parse().unwrap(),
            address: "10.0.0.9".parse().unwrap(),
            disabled: false,
            comment: String::new(),
        });
    let done = firewall::apply(&a, &b).unwrap();
    assert!(!done.replaced, "{done:?}");
    assert_eq!((done.rules_added, done.rules_removed), (2, 2), "{done:?}");
    assert_eq!(done.elements_changed, 2, "{done:?}");
    let after = handles();
    // Every rule that did not change kept its handle.
    for (c, h) in &before {
        let id = c.as_deref().unwrap_or("");
        if id == "cr:*3" || id == "cr:*5" {
            assert!(!after.contains(&(c.clone(), *h)), "{id} went");
        } else {
            assert!(after.contains(&(c.clone(), *h)), "{id} kept its handle");
        }
    }
    // And the kernel holds exactly `b`.
    let t = corerouter_firewall::nft::program(&b, &[]).unwrap();
    let h = held().unwrap();
    let sent: Vec<_> = t
        .rules
        .iter()
        .map(|r| (r.chain.clone(), r.exprs.clone(), r.comment.clone()))
        .collect();
    assert_eq!(h.rules, sent);
    assert_eq!(h.chains, t.chains);
    assert_eq!(h.sets, t.fw_sets);

    // A chain and its jump go; a list stops being filled (sets go).
    let mut c = b.clone();
    let list: Vec<FirewallRule> =
        c.ip.firewall
            .filter
            .iter()
            .filter(|r| ![7, 8, 21].contains(&r.id.0))
            .cloned()
            .collect();
    c.ip.firewall.filter = CowList::from(list);
    let done = firewall::apply(&b, &c).unwrap();
    assert!(!done.replaced, "{done:?}");
    let t = corerouter_firewall::nft::program(&c, &[]).unwrap();
    let h = held().unwrap();
    assert_eq!(h.chains, t.chains);
    assert_eq!(h.sets, t.fw_sets);
    assert_eq!(h.rules.len(), t.rules.len());

    // Back and forth: the diff in reverse.
    let done = firewall::apply(&c, &a).unwrap();
    assert!(!done.replaced, "{done:?}");
    assert_eq!(held().unwrap().rules.len(), 31);

    // Someone else changed our table: the diff sees it and replaces.
    assert!(
        Command::new("nft")
            .args([
                "add",
                "rule",
                "inet",
                "corerouter",
                "filter_input",
                "counter"
            ])
            .status()
            .unwrap()
            .success()
    );
    let done = firewall::apply(&a, &b).unwrap();
    assert!(done.replaced, "{done:?}");
    let t = corerouter_firewall::nft::program(&b, &[]).unwrap();
    assert_eq!(held().unwrap().rules.len(), t.rules.len());
    firewall::apply(&b, &Config::default()).unwrap();
    assert!(held().is_none());
}

fn dyn_entry(list: &str, addr: &str, secs: u64) -> DynamicAddress {
    DynamicAddress {
        list: list.parse().unwrap(),
        address: addr.parse().unwrap(),
        timeout_secs: secs,
        added_by_rule: false,
    }
}

#[test]
fn dynamic_entries_go_in_one_batch_and_merge() {
    if !ready() {
        return;
    }
    let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
    firewall::remove().unwrap();
    // Without any firewall: the table and the set are created.
    let many: Vec<DynamicAddress> = (0..1000u32)
        .map(|i| {
            let a = std::net::Ipv4Addr::from(0x0a00_0000 + i * 2);
            dyn_entry("flood", &a.to_string(), 300)
        })
        .collect();
    let ops: Vec<(bool, &DynamicAddress)> = many.iter().map(|d| (true, d)).collect();
    firewall::apply_dynamic(&ops).unwrap();
    let got = firewall::dynamic().unwrap();
    assert_eq!(got.len(), 1000);
    assert!(
        got.iter()
            .all(|d| d.timeout_secs > 290 && d.timeout_secs <= 300)
    );
    // IPv6 too, and a range.
    let v6 = dyn_entry("flood", "2001:db8::/64", 60);
    let r = dyn_entry("flood", "192.0.2.10-192.0.2.20", 60);
    firewall::apply_dynamic(&[(true, &v6), (true, &r)]).unwrap();
    let got = firewall::dynamic().unwrap();
    assert!(got.iter().any(|d| d.address.to_string() == "2001:db8::/64"));
    assert!(
        got.iter()
            .any(|d| d.address.to_string() == "192.0.2.10-192.0.2.20")
    );

    // A commit with a static entry in the same list, then a timed entry
    // inside it (the kernel refuses the overlap; the set is merged).
    let mut cfg = Config::default();
    cfg.ip
        .firewall
        .address_lists
        .push(corerouter_model::firewall::AddressListEntry {
            id: corerouter_model::ItemId(1),
            list: "flood".parse().unwrap(),
            address: "198.51.100.0/24".parse().unwrap(),
            disabled: false,
            comment: String::new(),
        });
    firewall::apply(&Config::default(), &cfg).unwrap();
    assert_eq!(
        firewall::dynamic().unwrap().len(),
        1002,
        "kept by the replace"
    );
    let inside = dyn_entry("flood", "198.51.100.7", 60);
    let across = dyn_entry("flood", "198.51.100.250-198.51.101.5", 60);
    firewall::apply_dynamic(&[(true, &inside), (true, &across)]).unwrap();
    let got = firewall::dynamic().unwrap();
    assert!(!got.iter().any(|d| d.address.to_string() == "198.51.100.7"));
    assert!(
        got.iter()
            .any(|d| d.address.to_string() == "198.51.101.0-198.51.101.5"),
        "{got:?}"
    );
    let text = listing();
    assert!(text.contains("198.51.100.0/24"), "{text}");

    // Removal, many at once.
    let ops: Vec<(bool, &DynamicAddress)> = many.iter().map(|d| (false, d)).collect();
    firewall::apply_dynamic(&ops).unwrap();
    let got = firewall::dynamic().unwrap();
    assert_eq!(got.len(), 3, "{got:?}");
    firewall::apply(&cfg, &Config::default()).unwrap();
    assert!(held().is_none());
}

/// A random rule from pools of values for every matcher and action.
fn arb_rule() -> impl Strategy<Value = (String, Vec<(String, String)>, String)> {
    let pick = |v: &'static [&'static str]| proptest::sample::select(v.to_vec());
    let matchers = (
        proptest::option::of(pick(&["tcp", "udp", "icmp", "!tcp", "47"])),
        proptest::option::of(pick(&[
            "22",
            "!80",
            "1000-2000",
            "!1000-2000",
            "22,80,443",
            "53,1000-2000",
            "!22,23",
        ])),
        proptest::option::of(pick(&["53", "1024-65535"])),
        proptest::option::of(pick(&[
            "10.0.0.0/8",
            "!10.1.0.0/16",
            "192.0.2.1",
            "10.16.0.0/12",
            "10.0.0.1-10.0.0.9",
            "!10.0.0.1-10.0.0.9",
            "2001:db8::/32",
            "2001:db8::1",
        ])),
        proptest::option::of(pick(&["blocked", "!blocked", "mgmt"])),
        proptest::option::of(pick(&["ether1", "!ether2"])),
        proptest::option::of(pick(&["LAN", "!WAN"])),
        proptest::option::of(pick(&[
            "new",
            "established,related",
            "!invalid,new",
            "established,related,new,invalid,untracked",
        ])),
        proptest::option::of(pick(&["5/1s,10", "1/1m,1"])),
        proptest::option::of(pick(&["0x10", "srcnat", "!dstnat"])),
    );
    let actions = pick(&[
        r#"{"type":"accept"}"#,
        r#"{"type":"drop"}"#,
        r#"{"type":"log","log_prefix":"x: "}"#,
        r#"{"type":"log"}"#,
        r#"{"type":"passthrough"}"#,
        r#"{"type":"return"}"#,
        r#"{"type":"reject","reject_with":"icmp-port-unreachable"}"#,
        r#"{"type":"add-dst-to-address-list","address_list":"seen","address_list_timeout":"5m"}"#,
        r#"{"type":"add-src-to-address-list","address_list":"blocked"}"#,
    ]);
    (pick(&["input", "forward", "output"]), matchers, actions).prop_map(|(chain, m, a)| {
        let mut pairs: Vec<(String, String)> = Vec::new();
        let mut put = |k: &str, v: Option<&str>| {
            if let Some(v) = v {
                pairs.push((k.to_owned(), v.to_owned()));
            }
        };
        let proto = m.0;
        put("protocol", proto);
        let ports = matches!(proto, Some("tcp" | "udp"));
        if ports {
            put("dst_port", m.1);
            put("src_port", m.2);
        }
        put("src_address", m.3);
        put("dst_address_list", m.4);
        put(
            if chain == "output" {
                "out_interface"
            } else {
                "in_interface"
            },
            m.5,
        );
        put(
            if chain == "output" {
                "out_interface_list"
            } else {
                "in_interface_list"
            },
            m.6,
        );
        put("connection_state", m.7);
        put("limit", m.8);
        match m.9 {
            Some("srcnat" | "!dstnat") => put("connection_nat_state", m.9),
            other => put("connection_mark", other.map(|_| "web")),
        }
        if proto == Some("icmp") {
            pairs.push(("icmp_options".into(), "8:0".into()));
        }
        (chain.to_owned(), pairs, a.to_owned())
    })
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, ..ProptestConfig::default() })]

    /// Random rules: what we load is what the kernel holds, and what
    /// `nft` loads from our text.
    #[test]
    fn random_rules_round_trip(rules in proptest::collection::vec(arb_rule(), 1..12)) {
        if !ready() {
            return Ok(());
        }
        let _one = KERNEL.lock().unwrap_or_else(|e| e.into_inner());
        let mut cfg = sample();
        let mut list = Vec::new();
        for (i, (chain, pairs, a)) in rules.iter().enumerate() {
            let pairs: Vec<(&str, &str)> = pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
            let Some(mm) = m(&pairs) else { continue };
            let Some(r) = rule(100 + i as u32, chain, mm, act(a).unwrap()) else { continue };
            list.push(r);
        }
        cfg.ip.firewall.filter = CowList::from(list);
        // Only configs the engine would commit.
        prop_assume!(corerouter_firewall::validate(&cfg).is_empty());
        same_both_ways(&cfg, &[]);
        firewall::remove().unwrap();
    }
}

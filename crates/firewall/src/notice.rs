//! Subscriber notices (G4.10) in the firewall's own table, `inet
//! corerouter`: the profiles' lists are its address-list sets, so a
//! subscriber entering or leaving a list (RADIUS, CoA, API, a lease) is one
//! set element, and the rules below never change per subscriber.
//!
//! | Chain | Hook | What |
//! |---|---|---|
//! | `notice_dstnat` | prerouting, `dstnat - 5` (ahead of the operator's dst-nat) | per profile and family, one rule: a member jumps to `notice_nat<4|6>_<profile>`, where port 80 of a member to the router's portal: every HTTP request (`intercept=http`) or only to the OS probe hosts' addresses (`sn-probe`); the walled garden and, for notice/throttle, those who saw the page (`sn-seen-<profile>`) are left alone |
//! | `notice_forward` | forward, `filter - 5` | block mode, the same jump to `notice_block<4|6>_<profile>`: the walled garden and DNS pass, TCP gets a reset and the rest ICMP administratively prohibited at once (an app fails fast instead of hanging) |
//!
//! A non-member's packet meets one set lookup per profile and hook, nothing
//! else (the chains of a profile run only for its members; measured in
//! `hal-linux/benches/netns_notice.rs`). A `return` leaves the profile's
//! chain: the packet goes on as if it were not a member.
//!
//! A verdict here does not skip the operator's own chains (nftables runs
//! every base chain of a hook): an accept means "not ours", a reject is
//! final. The router's own addresses are never redirected (`fib daddr type
//! != local`), so WebFig and the portal itself stay reachable.

use std::fmt::Write as _;

use corerouter_model::Config;
use corerouter_model::firewall::{AddrMatch, Name, PortRange, PortSet};

use crate::bytecode as bc;
use crate::program::{Chain, ChainType, Expr, FwSet, Hook, KeyKind, MetaKey, NatKind, Rule, Table};
use corerouter_model::subscriber_notice::{
    GARDEN_LIST, Intercept, Mode, PROBE_LIST, Profile, SubscriberNotices, seen_list,
};

/// The set of the walled garden's fixed prefixes (`dst_address`).
const GARDEN4: &str = "notice_g4";
const GARDEN6: &str = "notice_g6";

fn name(s: &str) -> Option<Name> {
    s.parse().ok()
}

/// Whether the config has a profile that acts.
pub fn on(cfg: &Config) -> bool {
    cfg.ip.subscriber_notice.active().next().is_some()
}

/// The address lists the notice rules read (each needs its sets).
pub fn lists(cfg: &Config) -> Vec<Name> {
    let sn = &cfg.ip.subscriber_notice;
    if !on(cfg) {
        return Vec::new();
    }
    let mut out: Vec<Name> = [GARDEN_LIST, PROBE_LIST]
        .iter()
        .filter_map(|s| name(s))
        .collect();
    for p in sn.active() {
        out.push(p.address_list.clone());
        if p.mode != Mode::Block
            && let Some(n) = name(&seen_list(&p.name))
        {
            out.push(n);
        }
    }
    out
}

fn one(p: u16) -> PortRange {
    PortRange { first: p, last: p }
}

/// The statement that sends a member's HTTP to the portal.
fn target(sn: &SubscriberNotices, v4: bool) -> (String, Vec<Expr>) {
    let port = sn.settings.port;
    match sn.settings.portal_address {
        Some(a @ std::net::IpAddr::V4(v)) if v4 => (
            format!("dnat ip to {v}:{port}"),
            bc::nat_exprs(NatKind::Dnat, a, a, Some(one(port))),
        ),
        Some(a @ std::net::IpAddr::V6(v)) if !v4 => (
            format!("dnat ip6 to [{v}]:{port}"),
            bc::nat_exprs(NatKind::Dnat, a, a, Some(one(port))),
        ),
        _ => (format!("redirect to :{port}"), bc::redir_exprs(port)),
    }
}

/// A profile's chain names (one per family and hook).
fn chain(kind: &str, p: &Profile, fam: &str) -> String {
    format!("notice_{kind}{fam}_{}", p.name)
}

/// One rule: its text, its expressions and its comment.
type NoticeRule = (String, Vec<Expr>, Option<String>);

/// `<ip> saddr|daddr @<set> <verdict>`.
fn lookup_rule(v4: bool, src: bool, set: &str, verdict: Expr) -> NoticeRule {
    let mut b = bc::RuleBuild::default();
    let (ip, dir) = (
        if v4 { "ip" } else { "ip6" },
        if src { "saddr" } else { "daddr" },
    );
    b.need_nfproto(!v4);
    b.push(
        format!("{ip} {dir} @{set}"),
        bc::addr_set_exprs(!v4, src, false, set),
    );
    let word = match &verdict {
        Expr::Jump { chain } => format!("jump {chain}"),
        _ => "return".to_owned(),
    };
    b.push(word, vec![verdict]);
    let (text, exprs) = b.finish();
    (text, exprs, None)
}

/// `[<probe>] tcp dport 80 fib daddr type != local counter <to> <tag>`.
fn intercept_rule(sn: &SubscriberNotices, p: &Profile, v4: bool) -> NoticeRule {
    let mut b = bc::RuleBuild::default();
    let (ip, fam) = if v4 { ("ip", "4") } else { ("ip6", "6") };
    if p.intercept == Intercept::Probes {
        b.need_nfproto(!v4);
        let set = format!("al{fam}_{PROBE_LIST}");
        b.push(
            format!("{ip} daddr @{set}"),
            bc::addr_set_exprs(!v4, false, false, &set),
        );
    }
    b.need_l4proto(6);
    b.push(
        "tcp dport 80",
        bc::port_exprs(false, false, &PortSet(vec![one(80)])),
    );
    b.push("fib daddr type != local", bc::fib_not_local());
    b.push("counter", vec![Expr::Counter]);
    let (to, exprs) = target(sn, v4);
    b.push(to, exprs);
    let tag = format!("notice:{}", p.name);
    b.push(format!("comment \"{tag}\""), Vec::new());
    let (text, exprs) = b.finish();
    (text, exprs, Some(tag))
}

/// The block chain's own rules (after the walled garden's returns).
fn block_rules(p: &Profile) -> [NoticeRule; 3] {
    let tag = format!("notice:{}", p.name);
    let mut dns = bc::l4proto_set(&[6, 17]);
    dns.extend(bc::port_exprs(false, false, &PortSet(vec![one(53)])));
    dns.push(Expr::Return);
    let mut rst = bc::meta_cmp(MetaKey::L4Proto, true, vec![6]);
    rst.push(Expr::Counter);
    rst.push(Expr::Reject {
        kind: bc::REJECT_TCP_RST,
        code: 0,
    });
    [
        (
            "meta l4proto { tcp, udp } th dport 53 return".to_owned(),
            dns,
            None,
        ),
        (
            format!("meta l4proto tcp counter reject with tcp reset comment \"{tag}\""),
            rst,
            Some(tag.clone()),
        ),
        (
            format!("counter reject with icmpx admin-prohibited comment \"{tag}\""),
            vec![
                Expr::Counter,
                Expr::Reject {
                    kind: bc::REJECT_ICMPX,
                    code: bc::ICMPX_ADMIN_PROHIBITED,
                },
            ],
            Some(tag),
        ),
    ]
}

/// One profile and family: the jump from each base chain (the only rule a
/// non-member's packet meets: one set lookup) and the profile's own chains.
fn rules(
    sn: &SubscriberNotices,
    p: &Profile,
    v4: bool,
    base: &mut [Vec<NoticeRule>; 2],
    chains: &mut Vec<(String, Vec<NoticeRule>)>,
) {
    let fam = if v4 { "4" } else { "6" };
    let member = format!("al{fam}_{}", p.address_list);
    let garden = [
        format!("al{fam}_{GARDEN_LIST}"),
        (if v4 { GARDEN4 } else { GARDEN6 }).to_owned(),
    ];
    let mut nat = Vec::new();
    for g in &garden {
        nat.push(lookup_rule(v4, false, g, Expr::Return));
    }
    if p.mode != Mode::Block {
        let seen = format!("al{fam}_{}", seen_list(&p.name));
        nat.push(lookup_rule(v4, true, &seen, Expr::Return));
    }
    nat.push(intercept_rule(sn, p, v4));
    let name = chain("nat", p, fam);
    base[0].push(lookup_rule(
        v4,
        true,
        &member,
        Expr::Jump {
            chain: name.clone(),
        },
    ));
    chains.push((name, nat));
    if p.mode == Mode::Block {
        let mut fwd = Vec::new();
        for g in &garden {
            fwd.push(lookup_rule(v4, false, g, Expr::Return));
        }
        fwd.extend(block_rules(p));
        let name = chain("block", p, fam);
        base[1].push(lookup_rule(
            v4,
            true,
            &member,
            Expr::Jump {
                chain: name.clone(),
            },
        ));
        chains.push((name, fwd));
    }
}

fn add_rules(out: &mut String, t: &mut Table, chain: &str, rules: Vec<NoticeRule>) {
    for (text, exprs, comment) in rules {
        let _ = writeln!(out, "\t\t{text}");
        t.rules.push(Rule {
            chain: chain.to_owned(),
            exprs,
            text,
            nft: None,
            comment,
        });
    }
}

/// The sets and chains, inside `table inet corerouter { … }` (empty when
/// no profile acts): the text, and the same objects into `t` (G2.8).
pub fn render(cfg: &Config, out: &mut String, t: &mut Table) {
    if !on(cfg) {
        return;
    }
    let sn = &cfg.ip.subscriber_notice;
    for (set, ty, v4) in [(GARDEN4, "ipv4_addr", true), (GARDEN6, "ipv6_addr", false)] {
        let nets: Vec<AddrMatch> = sn
            .walled_garden
            .iter()
            .filter(|g| !g.disabled)
            .filter_map(|g| g.dst_address)
            .filter(|n| n.addr().is_ipv4() == v4)
            .map(AddrMatch::Net)
            .collect();
        let items: Vec<String> = nets.iter().map(ToString::to_string).collect();
        let elems = if items.is_empty() {
            String::new()
        } else {
            format!("\t\telements = {{ {} }}\n", items.join(", "))
        };
        let _ = write!(
            out,
            "\tset {set} {{\n\t\ttype {ty}\n\t\tflags interval\n\t\tauto-merge\n{elems}\t}}\n"
        );
        let statics: Vec<&AddrMatch> = nets.iter().collect();
        t.fw_sets.push(FwSet {
            name: set.to_owned(),
            key: if v4 { KeyKind::Ipv4 } else { KeyKind::Ipv6 },
            interval: true,
            timeout: false,
            dynamic: false,
            size: None,
            auto_merge: true,
            elements: bc::interval_elements(&statics, &[]),
        });
    }
    let mut base: [Vec<NoticeRule>; 2] = [Vec::new(), Vec::new()];
    let mut chains = Vec::new();
    for p in sn.active() {
        for v4 in [true, false] {
            rules(sn, p, v4, &mut base, &mut chains);
        }
    }
    for (name, rules) in chains {
        let _ = writeln!(out, "\tchain {name} {{");
        t.chains.push(Chain {
            name: name.clone(),
            kind: ChainType::Filter,
            hook: Hook::Regular,
            priority: 0,
            priority_text: String::new(),
        });
        add_rules(out, t, &name, rules);
        let _ = writeln!(out, "\t}}");
    }
    let [nat, fwd] = base;
    let _ = writeln!(
        out,
        "\tchain notice_dstnat {{\n\t\ttype nat hook prerouting priority dstnat - 5; policy accept;"
    );
    t.chains.push(Chain {
        name: "notice_dstnat".into(),
        kind: ChainType::Nat,
        hook: Hook::Prerouting,
        priority: -105,
        priority_text: "dstnat - 5".into(),
    });
    add_rules(out, t, "notice_dstnat", nat);
    let _ = writeln!(out, "\t}}");
    if !fwd.is_empty() {
        let _ = writeln!(
            out,
            "\tchain notice_forward {{\n\t\ttype filter hook forward priority filter - 5; policy accept;"
        );
        t.chains.push(Chain {
            name: "notice_forward".into(),
            kind: ChainType::Filter,
            hook: Hook::Forward,
            priority: -5,
            priority_text: "filter - 5".into(),
        });
        add_rules(out, t, "notice_forward", fwd);
        let _ = writeln!(out, "\t}}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::ItemId;
    use corerouter_model::subscriber_notice::GardenEntry;

    fn cfg() -> Config {
        let mut c = Config::default();
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
    fn rules_per_mode() {
        let c = cfg();
        let mut out = String::new();
        render(&c, &mut out, &mut Table::default());
        assert!(out.contains("elements = { 203.0.113.0/24 }"), "{out}");
        // Block: every HTTP request, the rest refused at once.
        // One lookup per packet in each base chain, per profile and family.
        assert!(
            out.contains("ip saddr @al4_bloqueados jump notice_nat4_atraso"),
            "{out}"
        );
        assert!(
            out.contains("ip saddr @al4_bloqueados jump notice_block4_atraso"),
            "{out}"
        );
        assert!(
            out.contains("ip6 saddr @al6_bloqueados jump notice_block6_atraso"),
            "{out}"
        );
        let block = out.split("chain notice_block4_atraso {").nth(1).unwrap();
        assert!(
            block.contains("meta l4proto { tcp, udp } th dport 53 return"),
            "{out}"
        );
        assert!(
            block.contains("meta l4proto tcp counter reject with tcp reset"),
            "{out}"
        );
        assert!(
            block.contains("counter reject with icmpx admin-prohibited"),
            "{out}"
        );
        let nat = out.split("chain notice_nat4_atraso {").nth(1).unwrap();
        assert!(
            nat.contains("tcp dport 80 fib daddr type != local counter redirect to :8880"),
            "{out}"
        );
        // Notice: only the probes, nothing refused, the seen ones left alone.
        let nat = out.split("chain notice_nat4_aviso {").nth(1).unwrap();
        assert!(nat.contains("ip daddr @al4_sn-probe tcp dport 80"), "{out}");
        assert!(nat.contains("ip saddr @al4_sn-seen-aviso return"), "{out}");
        assert!(!out.contains("notice_block4_aviso"), "{out}");
        let l: Vec<String> = lists(&c).iter().map(ToString::to_string).collect();
        assert_eq!(
            l,
            [
                "sn-garden",
                "sn-probe",
                "bloqueados",
                "aviso",
                "sn-seen-aviso"
            ]
        );
    }

    #[test]
    fn portal_address_and_off() {
        let mut c = cfg();
        c.ip.subscriber_notice.settings.portal_address = Some("10.0.0.1".parse().unwrap());
        let mut out = String::new();
        render(&c, &mut out, &mut Table::default());
        assert!(out.contains("dnat ip to 10.0.0.1:8880"), "{out}");
        let nat6 = out.split("chain notice_nat6_atraso {").nth(1).unwrap();
        assert!(
            nat6.contains("tcp dport 80 fib daddr type != local counter redirect to :8880"),
            "{out}"
        );
        for p in &mut c.ip.subscriber_notice.profiles {
            p.disabled = true;
        }
        let mut out = String::new();
        render(&c, &mut out, &mut Table::default());
        assert!(out.is_empty() && lists(&c).is_empty());
    }
}

//! Shadowed rules: a rule that can never match, because an earlier rule of
//! the same chain already decides every packet it would see (G2.1b).
//!
//! Rule A shadows a later rule B when A is enabled, decides (accept, drop,
//! reject, return, NAT, a mark without passthrough) and A's matchers cover
//! B's: every matcher A has, B has too with a value inside A's (an address
//! inside A's prefix, ports inside A's ports, states among A's states, an
//! interface that is a member of A's interface list…). Matchers this cannot
//! compare (a `limit` on A, different address lists) count as "not
//! covered": the analysis misses some shadows but never reports a false
//! one.

use std::collections::BTreeMap;

use corerouter_model::firewall::{
    Action, AddrMatch, ConnState, Family, FirewallRule, Flag, Flags, Name, NatState, Neg, PortSet,
    Protocol, Table,
};
use corerouter_model::{Config, IfName, ItemId};

use crate::validate::family;

/// Bound on rule comparisons per table: a hostile 4096-rule chain would be
/// 8 M comparisons; past this the rest is not analysed (**estimado**).
pub const MAX_COMPARISONS: usize = 2_000_000;

/// Whether a matching packet stops in this chain.
fn decides(a: &Action) -> bool {
    !a.continues() && !matches!(a, Action::Jump { .. })
}

/// Whether every address `b` matches, `a` matches too.
fn addr_covers(a: &Neg<AddrMatch>, b: &Neg<AddrMatch>) -> bool {
    let disjoint = |x: &AddrMatch, y: &AddrMatch| {
        let (xl, xh) = x.bounds();
        let (yl, yh) = y.bounds();
        x.family() != y.family() || xh < yl || yh < xl
    };
    match (a.not, b.not) {
        (false, false) => a.value.covers(&b.value),
        // outside(B) ⊆ outside(A) ⟺ A ⊆ B
        (true, true) => b.value.covers(&a.value),
        (true, false) => disjoint(&a.value, &b.value),
        (false, true) => false,
    }
}

fn ports_covers(a: &Neg<PortSet>, b: &Neg<PortSet>) -> bool {
    let disjoint = a.value.0.iter().all(|x| {
        b.value
            .0
            .iter()
            .all(|y| x.last < y.first || y.last < x.first)
    });
    match (a.not, b.not) {
        (false, false) => a.value.covers(&b.value),
        (true, true) => b.value.covers(&a.value),
        (true, false) => disjoint,
        (false, true) => false,
    }
}

/// The values a flag matcher accepts, as a bit set (bit `n` = `all()[n]`;
/// the extra top bit is "none of them", e.g. a connection never NATed).
fn flag_bits<T: Flag>(n: &Neg<Flags<T>>, with_none: bool) -> u32 {
    let all = T::all();
    let mut bits = 0u32;
    for (i, f) in all.iter().enumerate() {
        if n.value.contains(*f) {
            bits |= 1 << i;
        }
    }
    let universe = ((1u32 << all.len()) - 1) | if with_none { 1 << all.len() } else { 0 };
    if n.not { universe & !bits } else { bits }
}

fn flags_covers<T: Flag>(a: &Neg<Flags<T>>, b: &Neg<Flags<T>>, with_none: bool) -> bool {
    let (a, b) = (flag_bits(a, with_none), flag_bits(b, with_none));
    b & !a == 0
}

fn eq_covers<T: PartialEq>(a: &Neg<T>, b: &Neg<T>) -> bool {
    a == b
}

fn proto_covers(a: &Neg<Protocol>, b: &Neg<Protocol>) -> bool {
    match (a.not, b.not) {
        (true, false) => a.value != b.value,
        _ => a == b,
    }
}

/// `a`'s matcher (if any) lets through everything `b`'s lets through.
fn field<T>(a: &Option<T>, b: &Option<T>, covers: impl Fn(&T, &T) -> bool) -> bool {
    match (a, b) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(x), Some(y)) => covers(x, y),
    }
}

/// The family of each rule, `None` when its matchers contradict.
fn family_covers(a: Option<Family>, b: Option<Family>) -> bool {
    match (a, b) {
        (Some(fa), Some(fb)) => fa == Family::Both || fa == fb,
        _ => false,
    }
}

/// An interface matcher of `a` against `b`'s interface and list matchers.
fn iface_covers(
    cfg: &Config,
    a_if: &Option<Neg<IfName>>,
    a_list: &Option<Neg<Name>>,
    b_if: &Option<Neg<IfName>>,
    b_list: &Option<Neg<Name>>,
) -> bool {
    let ifs = field(a_if, b_if, eq_covers);
    let lists = match (a_list, b_list, b_if) {
        (None, _, _) => true,
        (Some(a), Some(b), _) if a == b => true,
        // [LAN] covers ether2 when ether2 is a member of LAN.
        (Some(a), _, Some(i)) if !a.not && !i.not => cfg
            .interface_lists
            .interfaces_of(a.value.as_str())
            .any(|m| *m == i.value),
        _ => false,
    };
    ifs && lists
}

/// Whether every packet `b` matches, `a` matches too.
pub fn covers(cfg: &Config, a: &FirewallRule, b: &FirewallRule) -> bool {
    covers_as(cfg, (a, family(a).ok()), (b, family(b).ok()))
}

/// [`covers`] with the family of each rule already worked out.
fn covers_as(
    cfg: &Config,
    (a, fa): (&FirewallRule, Option<Family>),
    (b, fb): (&FirewallRule, Option<Family>),
) -> bool {
    let (ma, mb) = (&a.matchers, &b.matchers);
    ma.limit.is_none()
        && family_covers(fa, fb)
        && field(&ma.src_address, &mb.src_address, addr_covers)
        && field(&ma.dst_address, &mb.dst_address, addr_covers)
        && field(&ma.src_address_list, &mb.src_address_list, eq_covers)
        && field(&ma.dst_address_list, &mb.dst_address_list, eq_covers)
        && field(&ma.protocol, &mb.protocol, proto_covers)
        && field(&ma.src_port, &mb.src_port, ports_covers)
        && field(&ma.dst_port, &mb.dst_port, ports_covers)
        && iface_covers(
            cfg,
            &ma.in_interface,
            &ma.in_interface_list,
            &mb.in_interface,
            &mb.in_interface_list,
        )
        && iface_covers(
            cfg,
            &ma.out_interface,
            &ma.out_interface_list,
            &mb.out_interface,
            &mb.out_interface_list,
        )
        && field(&ma.connection_state, &mb.connection_state, |x, y| {
            flags_covers::<ConnState>(x, y, false)
        })
        && field(
            &ma.connection_nat_state,
            &mb.connection_nat_state,
            |x, y| flags_covers::<NatState>(x, y, true),
        )
        && field(&ma.icmp_options, &mb.icmp_options, |x, y| {
            x.kind == y.kind && x.code.is_none_or(|c| Some(c) == y.code)
        })
        && field(&ma.connection_mark, &mb.connection_mark, eq_covers)
        && field(&ma.packet_mark, &mb.packet_mark, eq_covers)
        && field(&ma.routing_mark, &mb.routing_mark, eq_covers)
}

/// Rules of `table` that can never match → the earlier rule that takes
/// their packets. Disabled rules and sections are neither judged nor
/// blamed.
pub fn shadowed(cfg: &Config, table: Table) -> BTreeMap<ItemId, ItemId> {
    let rules = cfg.ip.firewall.rules(table);
    let mut out = BTreeMap::new();
    let mut budget = MAX_COMPARISONS;
    // The earlier deciding rules of each chain, with their family: the
    // same comparisons in the same order as against every earlier rule,
    // without walking the other chains' rules nor working the family out
    // again for each pair (G0.31: 10 000 rules in 50 chains, 115 ms).
    let mut deciding: BTreeMap<&str, Vec<(&FirewallRule, Option<Family>)>> = BTreeMap::new();
    for b in rules.iter().filter(|r| !r.disabled && !r.section) {
        let fb = family(b).ok();
        let earlier = deciding.entry(b.chain.as_str()).or_default();
        for &(a, fa) in earlier.iter() {
            if budget == 0 {
                return out;
            }
            budget -= 1;
            if covers_as(cfg, (a, fa), (b, fb)) {
                out.insert(b.id, a.id);
                break;
            }
        }
        if decides(&b.action) {
            earlier.push((b, fb));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::{m, rule};

    type Spec<'a> = (u32, &'a str, &'a [(&'a str, &'a str)], Action);

    fn cfg(rules: &[Spec<'_>]) -> Config {
        let mut c = Config {
            interface_lists: crate::sample::sample().interface_lists,
            ..Config::default()
        };
        c.ip.firewall.filter = rules
            .iter()
            .map(|(id, chain, pairs, a)| rule(*id, chain, m(pairs).unwrap(), a.clone()).unwrap())
            .collect();
        c
    }

    #[test]
    fn simple_inclusions_are_found() {
        let c = cfg(&[
            (1, "input", &[("src_address", "10.0.0.0/8")], Action::Drop),
            (
                2,
                "input",
                &[("src_address", "10.1.0.0/16"), ("protocol", "tcp")],
                Action::Accept,
            ),
            (
                3,
                "forward",
                &[("src_address", "10.1.0.0/16")],
                Action::Accept,
            ),
            (
                4,
                "input",
                &[("protocol", "tcp"), ("dst_port", "22,80")],
                Action::Accept,
            ),
            (
                5,
                "input",
                &[("protocol", "tcp"), ("dst_port", "22")],
                Action::Drop,
            ),
            (6, "input", &[("in_interface_list", "LAN")], Action::Accept),
            (
                7,
                "input",
                &[("in_interface", "ether2"), ("protocol", "udp")],
                Action::Drop,
            ),
            (
                8,
                "input",
                &[("connection_state", "established,related")],
                Action::Accept,
            ),
            (9, "input", &[("connection_state", "related")], Action::Drop),
            (10, "input", &[("connection_state", "new")], Action::Drop),
        ]);
        let s = shadowed(&c, Table::Filter);
        assert_eq!(s.get(&ItemId(2)), Some(&ItemId(1)));
        assert_eq!(s.get(&ItemId(3)), None, "other chain");
        assert_eq!(s.get(&ItemId(5)), Some(&ItemId(4)));
        assert_eq!(s.get(&ItemId(7)), Some(&ItemId(6)), "ether2 is in LAN");
        assert_eq!(s.get(&ItemId(9)), Some(&ItemId(8)));
        assert_eq!(s.get(&ItemId(10)), None);
    }

    #[test]
    fn non_deciding_negated_and_limited_rules_do_not_shadow() {
        let log = Action::Log {
            log_prefix: String::new(),
        };
        let c = cfg(&[
            (1, "input", &[], log),
            (2, "input", &[("protocol", "tcp")], Action::Accept),
            (3, "input", &[("protocol", "!udp")], Action::Drop),
            (4, "input", &[("protocol", "icmp")], Action::Drop),
            (
                5,
                "input",
                &[("protocol", "icmp"), ("limit", "5/1s")],
                Action::Accept,
            ),
            (
                6,
                "input",
                &[("protocol", "icmp"), ("icmp_options", "8:0")],
                Action::Accept,
            ),
            (
                7,
                "input",
                &[("src_address", "!10.0.0.0/8")],
                Action::Accept,
            ),
            (
                8,
                "input",
                &[("src_address", "192.168.0.0/16")],
                Action::Accept,
            ),
            (
                9,
                "input",
                &[("src_address", "10.1.0.0/16")],
                Action::Accept,
            ),
        ]);
        let s = shadowed(&c, Table::Filter);
        assert_eq!(s.get(&ItemId(2)), None, "log goes on");
        assert_eq!(s.get(&ItemId(4)), Some(&ItemId(3)), "!udp takes icmp");
        assert_eq!(s.get(&ItemId(5)), Some(&ItemId(3)));
        assert_eq!(s.get(&ItemId(8)), Some(&ItemId(7)), "outside 10/8");
        assert_eq!(s.get(&ItemId(9)), None, "inside 10/8, !udp does not cover");
    }

    #[test]
    fn a_limit_before_never_shadows() {
        let c = cfg(&[
            (
                1,
                "input",
                &[("protocol", "icmp"), ("limit", "5/1s")],
                Action::Accept,
            ),
            (2, "input", &[("protocol", "icmp")], Action::Drop),
        ]);
        assert!(shadowed(&c, Table::Filter).is_empty());
    }
}

//! Where one packet ends in a chain: the rule that decides it, walking
//! jumps and returns like the kernel does. The engine's lockout check uses
//! it for the management connection (G2.1b); the packet tester of G2.1c
//! ([`crate::path`]) shows the same walk, chain after chain.
//!
//! What a config alone cannot know is assumed, always the same way:
//!
//! - the packet carries no connection, packet or routing mark;
//! - the connection was not NATed (`connection_nat_state` sees none);
//! - a `limit` is not exceeded (the rule matches);
//! - address lists hold their static entries plus the dynamic ones the
//!   caller passes; entries that rules added inside the kernel are unknown
//!   (not in the list).

use std::net::IpAddr;

use corerouter_model::firewall::{
    Action, AddrMatch, ConnState, DynamicAddress, Family, FirewallRule, Flag, Flags, Name, Neg,
    Protocol, Table,
};
use corerouter_model::{Config, ItemId};

use crate::validate::family;

/// One packet, as far as the matchers look at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub protocol: Protocol,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    /// ICMP type and code.
    pub icmp: Option<(u8, u8)>,
    pub in_interface: Option<String>,
    pub out_interface: Option<String>,
    pub state: ConnState,
}

impl Packet {
    pub fn family(&self) -> Family {
        Family::of(self.src)
    }
}

/// What happened to the packet in the chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
    Reject,
    /// `masquerade`, `src-nat` or `dst-nat` took it (nat table).
    Nat,
    /// Raw table: accepted without connection tracking; later chains see
    /// `connection_state=untracked`.
    Notrack,
}

impl Verdict {
    pub fn blocks(self) -> bool {
        matches!(self, Verdict::Drop | Verdict::Reject)
    }
}

/// The verdict and the rule that gave it (`None`: the chain's policy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Outcome {
    pub verdict: Verdict,
    pub rule: Option<ItemId>,
}

/// Bounds against hostile configs (the validator already refuses loops).
const MAX_DEPTH: usize = 64;
const MAX_STEPS: usize = 100_000;

/// Whether `ip` is in address list `name`.
pub fn in_list(cfg: &Config, dynamic: &[DynamicAddress], name: &Name, ip: IpAddr) -> bool {
    cfg.ip
        .firewall
        .address_lists
        .iter()
        .any(|e| !e.disabled && e.list == *name && e.address.contains(ip))
        || dynamic
            .iter()
            .any(|d| d.list == *name && d.address.contains(ip))
}

fn neg_is<T>(n: &Neg<T>, hit: bool) -> bool {
    hit != n.not
}

fn addr(m: &Option<Neg<AddrMatch>>, ip: IpAddr) -> bool {
    m.as_ref().is_none_or(|n| neg_is(n, n.value.contains(ip)))
}

fn flags<T: Flag>(m: &Option<Neg<Flags<T>>>, v: Option<T>) -> bool {
    m.as_ref()
        .is_none_or(|n| neg_is(n, v.is_some_and(|v| n.value.contains(v))))
}

/// Whether rule `r` matches `p` (see the module docs for the assumptions).
pub fn matches(cfg: &Config, dynamic: &[DynamicAddress], r: &FirewallRule, p: &Packet) -> bool {
    let m = &r.matchers;
    let fam_ok = family(r).is_ok_and(|f| f.and(p.family()).is_some());
    let list = |l: &Option<Neg<Name>>, ip: IpAddr| {
        l.as_ref()
            .is_none_or(|n| neg_is(n, in_list(cfg, dynamic, &n.value, ip)))
    };
    // A packet without that header: nftables' payload match fails, `!=` too.
    let port = |m: &Option<Neg<corerouter_model::firewall::PortSet>>, v: Option<u16>| {
        m.as_ref()
            .is_none_or(|n| v.is_some_and(|v| neg_is(n, n.value.contains(v))))
    };
    // No interface (output has no input one): `iifname != x` still matches.
    let iface = |m: &Option<Neg<corerouter_model::IfName>>, v: Option<&str>| {
        m.as_ref()
            .is_none_or(|n| neg_is(n, v.is_some_and(|v| n.value.as_str() == v)))
    };
    let iface_list = |m: &Option<Neg<Name>>, v: Option<&str>| {
        m.as_ref().is_none_or(|n| {
            let member = v.is_some_and(|v| {
                cfg.interface_lists
                    .interfaces_of(n.value.as_str())
                    .any(|i| i.as_str() == v)
            });
            neg_is(n, member)
        })
    };
    let icmp = m.icmp_options.is_none_or(|o| {
        p.icmp
            .is_some_and(|(t, c)| t == o.kind && o.code.is_none_or(|oc| oc == c))
    });
    // No marks, no NAT on the connection (module docs).
    let unmarked = |m: &Option<Neg<Name>>| m.as_ref().is_none_or(|n| n.not);
    fam_ok
        && addr(&m.src_address, p.src)
        && addr(&m.dst_address, p.dst)
        && list(&m.src_address_list, p.src)
        && list(&m.dst_address_list, p.dst)
        && m.protocol
            .as_ref()
            .is_none_or(|n| neg_is(n, n.value == p.protocol))
        && port(&m.src_port, p.src_port)
        && port(&m.dst_port, p.dst_port)
        && iface(&m.in_interface, p.in_interface.as_deref())
        && iface(&m.out_interface, p.out_interface.as_deref())
        && iface_list(&m.in_interface_list, p.in_interface.as_deref())
        && iface_list(&m.out_interface_list, p.out_interface.as_deref())
        && flags(&m.connection_state, Some(p.state))
        && flags(&m.connection_nat_state, None)
        && icmp
        && unmarked(&m.connection_mark)
        && unmarked(&m.packet_mark)
        && unmarked(&m.routing_mark)
}

/// The fate of `p` in built-in chain `chain` of `table`: the first
/// deciding rule, through jumps; the policy (accept) if none decides.
pub fn walk(
    cfg: &Config,
    dynamic: &[DynamicAddress],
    table: Table,
    chain: &str,
    p: &Packet,
) -> Outcome {
    walk_traced(cfg, dynamic, table, chain, p, None)
}

/// A rule the packet matched on its way through a chain (G2.1c): jumps,
/// returns, logs and marks that let it go on, and the one that decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub rule: ItemId,
    pub chain: Name,
    pub action: &'static str,
}

/// [`walk`], also listing in `hits` every rule that matched, in order.
pub fn walk_traced(
    cfg: &Config,
    dynamic: &[DynamicAddress],
    table: Table,
    chain: &str,
    p: &Packet,
    mut hits: Option<&mut Vec<Hit>>,
) -> Outcome {
    let rules: Vec<&FirewallRule> = cfg
        .ip
        .firewall
        .rules(table)
        .iter()
        .filter(|r| !r.disabled && !r.section)
        .collect();
    let policy = Outcome {
        verdict: Verdict::Accept,
        rule: None,
    };
    // (chain, index of the next rule to look at in `rules`)
    let mut stack: Vec<(String, usize)> = vec![(chain.to_owned(), 0)];
    let mut steps = 0usize;
    while let Some((current, start)) = stack.pop() {
        let mut i = start;
        let mut jumped = false;
        while let Some(r) = rules.get(i) {
            i += 1;
            steps += 1;
            if steps > MAX_STEPS {
                return policy;
            }
            if r.chain.as_str() != current || !matches(cfg, dynamic, r, p) {
                continue;
            }
            if let Some(h) = hits.as_deref_mut() {
                h.push(Hit {
                    rule: r.id,
                    chain: r.chain.clone(),
                    action: r.action.name(),
                });
            }
            let decided = |verdict| Outcome {
                verdict,
                rule: Some(r.id),
            };
            match &r.action {
                Action::Accept => return decided(Verdict::Accept),
                Action::Drop => return decided(Verdict::Drop),
                Action::Reject { .. } => return decided(Verdict::Reject),
                Action::Masquerade { .. } | Action::SrcNat { .. } | Action::DstNat { .. } => {
                    return decided(Verdict::Nat);
                }
                Action::Notrack => return decided(Verdict::Notrack),
                Action::Return => break,
                Action::Jump { jump_target } => {
                    if stack.len() + 2 > MAX_DEPTH {
                        return policy;
                    }
                    stack.push((current.clone(), i));
                    stack.push((jump_target.as_str().to_owned(), 0));
                    jumped = true;
                    break;
                }
                // A mark without passthrough stops like accept (`… accept`).
                a if !a.continues() => return decided(Verdict::Accept),
                _ => {}
            }
        }
        if !jumped && stack.is_empty() {
            return policy;
        }
    }
    policy
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::{act, m, rule};

    fn cfg(rules: Vec<FirewallRule>) -> Config {
        let mut c = Config {
            interface_lists: crate::sample::sample().interface_lists,
            ..Config::default()
        };
        c.ip.firewall.filter = rules.into();
        c
    }

    fn ssh(from: &str, iface: &str, state: ConnState) -> Packet {
        Packet {
            src: from.parse().unwrap(),
            dst: "192.0.2.1".parse().unwrap(),
            protocol: Protocol::TCP,
            src_port: Some(50_000),
            dst_port: Some(22),
            icmp: None,
            in_interface: Some(iface.into()),
            out_interface: None,
            state,
        }
    }

    #[test]
    fn first_deciding_rule_wins_through_jumps() {
        let c = cfg(vec![
            rule(
                1,
                "input",
                m(&[("connection_state", "established,related")]).unwrap(),
                Action::Accept,
            )
            .unwrap(),
            rule(
                2,
                "input",
                m(&[]).unwrap(),
                act(r#"{"type":"jump","jump_target":"mgmt"}"#).unwrap(),
            )
            .unwrap(),
            rule(
                3,
                "mgmt",
                m(&[("in_interface_list", "LAN")]).unwrap(),
                Action::Return,
            )
            .unwrap(),
            rule(4, "mgmt", m(&[]).unwrap(), Action::Drop).unwrap(),
            rule(5, "input", m(&[]).unwrap(), Action::Accept).unwrap(),
        ]);
        let walk = |p: &Packet| walk(&c, &[], Table::Filter, "input", p);
        let est = walk(&ssh("10.0.0.9", "ether1", ConnState::Established));
        assert_eq!((est.verdict, est.rule), (Verdict::Accept, Some(ItemId(1))));
        let wan = walk(&ssh("10.0.0.9", "ether1", ConnState::New));
        assert_eq!((wan.verdict, wan.rule), (Verdict::Drop, Some(ItemId(4))));
        let lan = walk(&ssh("10.0.0.9", "ether2", ConnState::New));
        assert_eq!((lan.verdict, lan.rule), (Verdict::Accept, Some(ItemId(5))));
        let empty = walk_empty();
        assert_eq!(empty.rule, None);
    }

    fn walk_empty() -> Outcome {
        walk(
            &Config::default(),
            &[],
            Table::Filter,
            "input",
            &ssh("10.0.0.9", "ether1", ConnState::New),
        )
    }

    #[test]
    fn address_lists_negation_and_assumptions() {
        let mut c = cfg(vec![
            rule(
                1,
                "input",
                m(&[("src_address_list", "blocked")]).unwrap(),
                Action::Drop,
            )
            .unwrap(),
            rule(
                2,
                "input",
                m(&[("connection_mark", "x")]).unwrap(),
                Action::Drop,
            )
            .unwrap(),
            rule(
                3,
                "input",
                m(&[("protocol", "!tcp")]).unwrap(),
                Action::Drop,
            )
            .unwrap(),
        ]);
        c.ip.firewall.address_lists = crate::sample::sample().ip.firewall.address_lists.clone();
        let p = ssh("203.0.113.5", "ether1", ConnState::New);
        assert_eq!(
            walk(&c, &[], Table::Filter, "input", &p).rule,
            Some(ItemId(1))
        );
        let other = ssh("198.51.100.50", "ether1", ConnState::New);
        assert_eq!(walk(&c, &[], Table::Filter, "input", &other).rule, None);
        let dynamic = [DynamicAddress {
            list: "blocked".parse().unwrap(),
            address: "198.51.100.50".parse().unwrap(),
            timeout_secs: 60,
            added_by_rule: false,
        }];
        assert_eq!(
            walk(&c, &dynamic, Table::Filter, "input", &other).rule,
            Some(ItemId(1))
        );
    }
}

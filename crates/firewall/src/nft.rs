//! The nftables ruleset of a config: one table, `inet corerouter`, that we
//! own entirely (other tables are never read or touched).
//!
//! | RouterOS | nftables |
//! |---|---|
//! | chain `input` of filter | base chain `filter_input` (hook input, priority filter) |
//! | chain `srcnat` / `dstnat` | `nat_srcnat` (postrouting, srcnat) / `nat_dstnat` (prerouting, dstnat) |
//! | mangle chains | `mangle_<chain>` (priority mangle; `output` is a `route` chain so a routing mark reroutes) |
//! | custom chain `x` of table `t` | regular chain `t_x` (reached by `jump`) |
//! | address list `x` | sets `al4_x` (ipv4) and `al6_x` (ipv6), `interval, timeout`, `auto-merge` |
//! | list `x` filled by `add-*-to-address-list` | also `ad4_x`/`ad6_x` (`dynamic, timeout`, at most 65 536) |
//! | interface list `x` | set `il_x` of `ifname` |
//! | rule `*N` | rule(s) with `comment "cr:*N"`, always with a `counter` |
//!
//! The kernel cannot add to an interval set from the packet path, so a list
//! that a rule fills gets a second, plain set (`ad*`); a rule matching that
//! list matches either set: `@al4_x`, or `@ad4_x` and not `@al4_x` (two
//! disjoint kernel rules, so a non-terminal action never runs twice), and
//! `!@x` is `!= @al4_x != @ad4_x` in one rule.
//!
//! A rule for both families that matches an address list (or fills one)
//! becomes one kernel rule per family; everything else is one rule. Marks
//! are names in RouterOS and numbers in the kernel ([`mark_value`]):
//! connection mark = `ct mark`; packet mark = low 16 bits of the packet
//! mark, routing mark = high 16 bits (for `ip rule fwmark … /0xffff0000`).
//!
//! Every name that reaches the text is a validated [`Name`]/`IfName`
//! (letters, digits, `-`, `_`, `.`), and the log prefix is checked by the
//! validator; [`quoted`] still drops anything that could break a string.

use std::collections::BTreeSet;

use std::fmt::Write as _;

use corerouter_model::firewall::{
    Action, AddrMatch, ConnState, DynamicAddress, Family, FirewallRule, Flags, Name, NatState,
    NatTarget, Neg, PortRange, PortSet, Protocol, RejectWith, Table,
};
use corerouter_model::{Config, IfName, ItemId};

use crate::graph;
use crate::validate::family;

/// The only nftables table CoreRouter writes.
pub const TABLE: &str = "corerouter";

/// What a mark name is for (they hash into different spaces).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MarkKind {
    Connection,
    Packet,
    Routing,
}

/// The kernel number of a mark name: FNV-1a of the name, stable across
/// commits and reboots (no table to keep), never 0 (0 is "no mark").
/// Packet and routing marks get 16 bits each; collisions are refused by
/// the validator.
pub fn mark_value(kind: MarkKind, name: &Name) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for b in name.as_str().bytes() {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    match kind {
        MarkKind::Connection => h.max(1),
        MarkKind::Packet => ((h ^ (h >> 16)) & 0xffff).max(1),
        MarkKind::Routing => (((h ^ (h >> 16)) & 0xffff).max(1)) << 16,
    }
}

/// The tag that ties kernel rules back to rule `id` (counters, PR 3).
pub fn rule_tag(id: ItemId) -> String {
    format!("cr:{id}")
}

pub fn chain_name(table: Table, chain: &str) -> String {
    format!("{}_{chain}", table.name())
}

/// A string literal for nftables: only what cannot break out of quotes.
pub fn quoted(s: &str) -> String {
    let clean: String = s
        .chars()
        .filter(|c| (' '..='~').contains(c) && *c != '"' && *c != '\\')
        .collect();
    format!("\"{clean}\"")
}

fn base_hook(table: Table, chain: &str) -> Option<(&'static str, &'static str, &'static str)> {
    // (type, hook, priority)
    Some(match (table, chain) {
        (Table::Filter, "input") => ("filter", "input", "filter"),
        (Table::Filter, "forward") => ("filter", "forward", "filter"),
        (Table::Filter, "output") => ("filter", "output", "filter"),
        (Table::Nat, "dstnat") => ("nat", "prerouting", "dstnat"),
        (Table::Nat, "srcnat") => ("nat", "postrouting", "srcnat"),
        (Table::Mangle, "prerouting") => ("filter", "prerouting", "mangle"),
        (Table::Mangle, "input") => ("filter", "input", "mangle"),
        (Table::Mangle, "forward") => ("filter", "forward", "mangle"),
        (Table::Mangle, "output") => ("route", "output", "mangle"),
        (Table::Mangle, "postrouting") => ("filter", "postrouting", "mangle"),
        _ => return None,
    })
}

fn set_v4(list: &Name) -> String {
    format!("al4_{list}")
}

fn set_v6(list: &Name) -> String {
    format!("al6_{list}")
}

fn dyn_v4(list: &Name) -> String {
    format!("ad4_{list}")
}

fn dyn_v6(list: &Name) -> String {
    format!("ad6_{list}")
}

/// Bound of a list's dynamic set: a flood of new sources cannot grow it
/// without limit (**estimado**).
pub const DYNAMIC_SET_SIZE: u32 = 65_536;

/// Lists that a rule fills (`add-*-to-address-list`), disabled rules
/// included so enabling one does not change the sets.
pub fn filled_lists(cfg: &Config) -> BTreeSet<&Name> {
    let fw = &cfg.ip.firewall;
    Table::ALL
        .iter()
        .flat_map(|t| fw.rules(*t))
        .filter(|r| !r.section)
        .filter_map(|r| r.action.fills_list())
        .collect()
}

fn set_if(list: &Name) -> String {
    format!("il_{list}")
}

fn op<T>(n: &Neg<T>) -> &'static str {
    if n.not { "!= " } else { "" }
}

fn addr_text(a: &AddrMatch) -> String {
    a.to_string()
}

fn ports_text(p: &PortSet) -> String {
    match p.0.as_slice() {
        [one] => one.to_string(),
        many => format!(
            "{{ {} }}",
            many.iter()
                .map(PortRange::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

fn proto_text(p: Protocol) -> String {
    match p.0 {
        1 => "icmp".into(),
        6 => "tcp".into(),
        17 => "udp".into(),
        47 => "gre".into(),
        50 => "esp".into(),
        51 => "ah".into(),
        58 => "ipv6-icmp".into(),
        132 => "sctp".into(),
        136 => "udplite".into(),
        n => n.to_string(),
    }
}

fn state_name(s: ConnState) -> &'static str {
    s.name()
}

fn states_text(f: &Neg<Flags<ConnState>>) -> String {
    let names: Vec<&str> = f.value.0.iter().map(|s| state_name(*s)).collect();
    if f.not {
        format!("ct state & ({}) == 0", names.join(" | "))
    } else if let [one] = names.as_slice() {
        format!("ct state {one}")
    } else {
        format!("ct state {{ {} }}", names.join(", "))
    }
}

fn nat_states_text(f: &Neg<Flags<NatState>>) -> String {
    let names: Vec<&str> = f
        .value
        .0
        .iter()
        .map(|s| match s {
            NatState::Srcnat => "snat",
            NatState::Dstnat => "dnat",
        })
        .collect();
    format!(
        "ct status & ({}) {} 0",
        names.join(" | "),
        if f.not { "==" } else { "!=" }
    )
}

fn nat_to(t: &NatTarget, ports: Option<PortRange>) -> String {
    let v6 = t.family() == Family::Ipv6;
    let addr = |a: std::net::IpAddr| {
        if v6 && ports.is_some() {
            format!("[{a}]")
        } else {
            a.to_string()
        }
    };
    let mut s = addr(t.first);
    if t.first != t.last {
        s.push('-');
        s.push_str(&addr(t.last));
    }
    if let Some(p) = ports {
        let _ = write!(s, ":{p}");
    }
    s
}

/// Which set a positive address-list matcher looks at, when its list also
/// has a dynamic set (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Pick {
    /// `@al4_x` (also the only choice for lists without a dynamic set).
    Static,
    /// `@ad4_x` and not `@al4_x`.
    Dynamic,
}

/// The nftables statements of rule `r` for one family (`Both` = no
/// family match), matchers first, then counter, action and tag.
fn statements(
    table: Table,
    r: &FirewallRule,
    fam: Family,
    filled: &BTreeSet<&Name>,
    picks: (Pick, Pick),
) -> String {
    let m = &r.matchers;
    let mut s: Vec<String> = Vec::new();
    match fam {
        Family::Ipv4 => s.push("meta nfproto ipv4".into()),
        Family::Ipv6 => s.push("meta nfproto ipv6".into()),
        Family::Both => {}
    }
    let ip = if fam == Family::Ipv6 { "ip6" } else { "ip" };
    if let Some(i) = &m.in_interface {
        s.push(format!("iifname {}{}", op(i), quoted(i.value.as_str())));
    }
    if let Some(l) = &m.in_interface_list {
        s.push(format!("iifname {}@{}", op(l), set_if(&l.value)));
    }
    if let Some(i) = &m.out_interface {
        s.push(format!("oifname {}{}", op(i), quoted(i.value.as_str())));
    }
    if let Some(l) = &m.out_interface_list {
        s.push(format!("oifname {}@{}", op(l), set_if(&l.value)));
    }
    if let Some(a) = &m.src_address {
        s.push(format!("{ip} saddr {}{}", op(a), addr_text(&a.value)));
    }
    if let Some(a) = &m.dst_address {
        s.push(format!("{ip} daddr {}{}", op(a), addr_text(&a.value)));
    }
    let set = |l: &Name| {
        if fam == Family::Ipv6 {
            set_v6(l)
        } else {
            set_v4(l)
        }
    };
    let dyn_set = |l: &Name| {
        if fam == Family::Ipv6 {
            dyn_v6(l)
        } else {
            dyn_v4(l)
        }
    };
    for (dir, list, pick) in [
        ("saddr", &m.src_address_list, picks.0),
        ("daddr", &m.dst_address_list, picks.1),
    ] {
        let Some(l) = list else { continue };
        if !filled.contains(&l.value) {
            s.push(format!("{ip} {dir} {}@{}", op(l), set(&l.value)));
        } else if l.not {
            s.push(format!("{ip} {dir} != @{}", set(&l.value)));
            s.push(format!("{ip} {dir} != @{}", dyn_set(&l.value)));
        } else if pick == Pick::Static {
            s.push(format!("{ip} {dir} @{}", set(&l.value)));
        } else {
            s.push(format!("{ip} {dir} @{}", dyn_set(&l.value)));
            s.push(format!("{ip} {dir} != @{}", set(&l.value)));
        }
    }
    if let Some(p) = &m.protocol {
        s.push(format!("meta l4proto {}{}", op(p), proto_text(p.value)));
    }
    if let Some(p) = &m.src_port {
        s.push(format!("th sport {}{}", op(p), ports_text(&p.value)));
    }
    if let Some(p) = &m.dst_port {
        s.push(format!("th dport {}{}", op(p), ports_text(&p.value)));
    }
    if let Some(i) = &m.icmp_options {
        let v6 = m
            .protocol
            .as_ref()
            .is_some_and(|p| p.value == Protocol::ICMPV6);
        let kw = if v6 { "icmpv6" } else { "icmp" };
        s.push(format!("{kw} type {}", i.kind));
        if let Some(c) = i.code {
            s.push(format!("{kw} code {c}"));
        }
    }
    if let Some(f) = &m.connection_state {
        s.push(states_text(f));
    }
    if let Some(f) = &m.connection_nat_state {
        s.push(nat_states_text(f));
    }
    if let Some(n) = &m.connection_mark {
        s.push(format!(
            "ct mark {}0x{:08x}",
            op(n),
            mark_value(MarkKind::Connection, &n.value)
        ));
    }
    if let Some(n) = &m.packet_mark {
        s.push(format!(
            "meta mark & 0x0000ffff {} 0x{:08x}",
            if n.not { "!=" } else { "==" },
            mark_value(MarkKind::Packet, &n.value)
        ));
    }
    if let Some(n) = &m.routing_mark {
        s.push(format!(
            "meta mark & 0xffff0000 {} 0x{:08x}",
            if n.not { "!=" } else { "==" },
            mark_value(MarkKind::Routing, &n.value)
        ));
    }
    if let Some(l) = &m.limit {
        s.push(format!(
            "limit rate {}/{} burst {} packets",
            l.count,
            l.period.name(),
            l.burst
        ));
    }
    s.push("counter".into());
    let stop = |pass: bool| {
        if pass {
            String::new()
        } else {
            " accept".into()
        }
    };
    let act = match &r.action {
        Action::Accept => "accept".into(),
        Action::Drop => "drop".into(),
        Action::Reject { reject_with } => match reject_with {
            RejectWith::TcpReset => "reject with tcp reset".into(),
            RejectWith::IcmpNoRoute => "reject with icmpx type no-route".into(),
            RejectWith::IcmpAdminProhibited => "reject with icmpx type admin-prohibited".into(),
            RejectWith::IcmpAddressUnreachable => "reject with icmpx type host-unreachable".into(),
            RejectWith::IcmpPortUnreachable => "reject with icmpx type port-unreachable".into(),
        },
        Action::Jump { jump_target } => {
            format!("jump {}", chain_name(table, jump_target.as_str()))
        }
        Action::Return => "return".into(),
        Action::Log { log_prefix } if log_prefix.is_empty() => "log".into(),
        Action::Log { log_prefix } => format!("log prefix {}", quoted(log_prefix)),
        Action::Passthrough => String::new(),
        Action::Masquerade { to_ports: None } => "masquerade".into(),
        Action::Masquerade { to_ports: Some(p) } => format!("masquerade to :{p}"),
        Action::SrcNat {
            to_addresses,
            to_ports,
        } => format!(
            "snat {} to {}",
            if to_addresses.family() == Family::Ipv6 {
                "ip6"
            } else {
                "ip"
            },
            nat_to(to_addresses, *to_ports)
        ),
        Action::DstNat {
            to_addresses,
            to_ports,
        } => format!(
            "dnat {} to {}",
            if to_addresses.family() == Family::Ipv6 {
                "ip6"
            } else {
                "ip"
            },
            nat_to(to_addresses, *to_ports)
        ),
        Action::MarkConnection {
            new_connection_mark,
            passthrough,
        } => format!(
            "ct mark set 0x{:08x}{}",
            mark_value(MarkKind::Connection, new_connection_mark),
            stop(*passthrough)
        ),
        Action::MarkPacket {
            new_packet_mark,
            passthrough,
        } => format!(
            "meta mark set meta mark & 0xffff0000 | 0x{:08x}{}",
            mark_value(MarkKind::Packet, new_packet_mark),
            stop(*passthrough)
        ),
        Action::MarkRouting {
            new_routing_mark,
            passthrough,
        } => format!(
            "meta mark set meta mark & 0x0000ffff | 0x{:08x}{}",
            mark_value(MarkKind::Routing, new_routing_mark),
            stop(*passthrough)
        ),
        Action::AddSrcToAddressList {
            address_list,
            address_list_timeout,
        }
        | Action::AddDstToAddressList {
            address_list,
            address_list_timeout,
        } => {
            let dir = if matches!(r.action, Action::AddSrcToAddressList { .. }) {
                "saddr"
            } else {
                "daddr"
            };
            let timeout = address_list_timeout
                .map(|t| format!(" timeout {}s", t.secs()))
                .unwrap_or_default();
            format!("add @{} {{ {ip} {dir}{timeout} }}", dyn_set(address_list))
        }
    };
    if !act.is_empty() {
        s.push(act);
    }
    s.push(format!("comment {}", quoted(&rule_tag(r.id))));
    s.join(" ")
}

/// Kernel rules for `r`: one, or one per family when it uses address lists
/// and applies to both. Empty when it can never match (invalid families,
/// which the validator reports).
pub fn kernel_rules(table: Table, r: &FirewallRule, filled: &BTreeSet<&Name>) -> Vec<String> {
    let Ok(fam) = family(r) else {
        return Vec::new();
    };
    let m = &r.matchers;
    let lists = m.src_address_list.is_some()
        || m.dst_address_list.is_some()
        || r.action.fills_list().is_some();
    let families = if fam == Family::Both && lists {
        vec![Family::Ipv4, Family::Ipv6]
    } else {
        vec![fam]
    };
    // A positive match on a list with a dynamic set: one rule per set.
    let picks = |l: &Option<Neg<Name>>| match l {
        Some(n) if !n.not && filled.contains(&n.value) => vec![Pick::Static, Pick::Dynamic],
        _ => vec![Pick::Static],
    };
    let mut out = Vec::new();
    for f in families {
        for src in picks(&m.src_address_list) {
            for dst in picks(&m.dst_address_list) {
                out.push(statements(table, r, f, filled, (src, dst)));
            }
        }
    }
    out
}

/// The address-list names the ruleset needs a set for.
fn address_lists<'a>(cfg: &'a Config, dynamic: &'a [DynamicAddress]) -> BTreeSet<&'a Name> {
    let fw = &cfg.ip.firewall;
    let mut out: BTreeSet<&Name> = fw.address_lists.iter().map(|e| &e.list).collect();
    out.extend(dynamic.iter().filter(|d| !d.added_by_rule).map(|d| &d.list));
    out.extend(filled_lists(cfg));
    for table in Table::ALL {
        for r in fw.rules(table) {
            out.extend(r.matchers.src_address_list.as_ref().map(|n| &n.value));
            out.extend(r.matchers.dst_address_list.as_ref().map(|n| &n.value));
        }
    }
    out
}

fn elements(items: &[String]) -> String {
    if items.is_empty() {
        String::new()
    } else {
        format!("\t\telements = {{ {} }}\n", items.join(", "))
    }
}

/// The body of `table inet corerouter`, or `None` when the config has no
/// firewall at all (no rules, no address-list entries, no dynamic entry from a command):
/// then the table should not exist.
pub fn render(cfg: &Config, dynamic: &[DynamicAddress]) -> Option<String> {
    let fw = &cfg.ip.firewall;
    if fw.is_empty() && dynamic.iter().all(|d| d.added_by_rule) {
        return None;
    }
    let mut out = String::new();
    let _ = writeln!(out, "table inet {TABLE} {{");
    let filled = filled_lists(cfg);

    for list in address_lists(cfg, dynamic) {
        for (fam, name, ty) in [
            (Family::Ipv4, set_v4(list), "ipv4_addr"),
            (Family::Ipv6, set_v6(list), "ipv6_addr"),
        ] {
            let mut items: Vec<String> = fw
                .address_lists
                .iter()
                .filter(|e| !e.disabled && e.list == *list && e.address.family() == fam)
                .map(|e| addr_text(&e.address))
                .collect();
            // Entries a rule added go back to the dynamic set below (and
            // are dropped once no rule fills the list).
            items.extend(
                dynamic
                    .iter()
                    .filter(|d| d.list == *list && d.address.family() == fam)
                    .filter(|d| !d.added_by_rule)
                    .map(|d| {
                        format!(
                            "{} timeout {}s",
                            addr_text(&d.address),
                            d.timeout_secs.max(1)
                        )
                    }),
            );
            let _ = write!(
                out,
                "\tset {name} {{\n\t\ttype {ty}\n\t\tflags interval, timeout\n\t\tauto-merge\n{}\t}}\n",
                elements(&items)
            );
        }
        if !filled.contains(list) {
            continue;
        }
        for (fam, name, ty) in [
            (Family::Ipv4, dyn_v4(list), "ipv4_addr"),
            (Family::Ipv6, dyn_v6(list), "ipv6_addr"),
        ] {
            // Only single addresses fit a plain set.
            let items: Vec<String> = dynamic
                .iter()
                .filter(|d| d.added_by_rule && d.list == *list && d.address.family() == fam)
                .filter_map(|d| match d.address {
                    AddrMatch::Net(n) if n.prefix_len() == n.max_prefix_len() => {
                        Some(if d.timeout_secs > 0 {
                            format!("{} timeout {}s", n.addr(), d.timeout_secs)
                        } else {
                            n.addr().to_string()
                        })
                    }
                    _ => None,
                })
                .collect();
            let _ = write!(
                out,
                "\tset {name} {{\n\t\ttype {ty}\n\t\tsize {DYNAMIC_SET_SIZE}\n\t\tflags dynamic, timeout\n{}\t}}\n",
                elements(&items)
            );
        }
    }
    for list in &cfg.interface_lists.lists {
        let items: Vec<String> = cfg
            .interface_lists
            .interfaces_of(list.name.as_str())
            .map(|i: &IfName| quoted(i.as_str()))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let _ = write!(
            out,
            "\tset {} {{\n\t\ttype ifname\n{}\t}}\n",
            set_if(&list.name),
            elements(&items)
        );
    }

    for table in Table::ALL {
        let rules = fw.rules(table);
        let live: Vec<&FirewallRule> = rules.iter().filter(|r| !r.disabled && !r.section).collect();
        let mut chains: Vec<String> = table
            .builtin_chains()
            .iter()
            .filter(|c| live.iter().any(|r| r.chain.as_str() == **c))
            .map(|c| (*c).to_owned())
            .collect();
        chains.extend(
            graph::custom_chains(table, rules)
                .into_iter()
                .map(|n| n.as_str().to_owned()),
        );
        for chain in chains {
            let _ = writeln!(out, "\tchain {} {{", chain_name(table, &chain));
            if let Some((ty, hook, prio)) = base_hook(table, &chain) {
                let _ = writeln!(
                    out,
                    "\t\ttype {ty} hook {hook} priority {prio}; policy accept;"
                );
            }
            for r in live.iter().filter(|r| r.chain.as_str() == chain) {
                for line in kernel_rules(table, r, &filled) {
                    let _ = writeln!(out, "\t\t{line}");
                }
            }
            let _ = writeln!(out, "\t}}");
        }
    }
    let _ = writeln!(out, "}}");
    Some(out)
}

/// The text `nft -f -` applies as one transaction: our table is replaced
/// whole (created empty first so the delete never fails), or removed when
/// the config has no firewall.
pub fn script(cfg: &Config, dynamic: &[DynamicAddress]) -> String {
    let mut s = format!("table inet {TABLE}\ndelete table inet {TABLE}\n");
    if let Some(body) = render(cfg, dynamic) {
        s.push_str(&body);
    }
    s
}

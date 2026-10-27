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
//! | subscriber-notice profiles (G4.10) | chains `notice_dstnat` / `notice_forward` ([`crate::notice`]) |
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

use std::collections::{BTreeMap, BTreeSet};

use std::fmt::Write as _;

use corerouter_model::firewall::{
    Action, AddrMatch, AddressListEntry, ConnState, DynamicAddress, Family, FirewallRule, Flags,
    Name, NatState, NatTarget, Neg, PortRange, PortSet, Protocol, RejectWith, Table,
};
use corerouter_model::{Config, IfName, ItemId};

use crate::graph;
use crate::program;
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

/// The tag that ties kernel rules back to rule `id` (counters, [`rule_of`]).
pub fn rule_tag(id: ItemId) -> String {
    format!("cr:{id}")
}

pub fn chain_name(table: Table, chain: &str) -> String {
    format!("{}_{chain}", table.name())
}

/// The table and chain of kernel chain `name` (`filter_input` →
/// filter/input); `None` for chains that are not a rule table's
/// (subscriber notices). Reverse of [`chain_name`] (G2.1c).
pub fn table_of_chain(name: &str) -> Option<(Table, &str)> {
    let (t, chain) = name.split_once('_')?;
    let table = t.parse::<Table>().ok()?;
    (!chain.is_empty()).then_some((table, chain))
}

/// The rule behind a kernel rule: its chain and its `cr:*N` comment
/// (G2.1c: counters and trace).
pub fn rule_of(chain: &str, comment: Option<&str>) -> Option<(Table, ItemId)> {
    let (table, _) = table_of_chain(chain)?;
    let id = comment?.strip_prefix("cr:")?.parse().ok()?;
    Some((table, id))
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
        // Priority raw (-300): before conntrack (-200), so notrack works.
        (Table::Raw, "prerouting") => ("filter", "prerouting", "raw"),
        (Table::Raw, "output") => ("filter", "output", "raw"),
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
        _ => format!("@{}", crate::bytecode::port_set_name(p)),
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
        format!("ct state {}", names.join(","))
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
/// family match), matchers first, then counter, action and tag: the text
/// `nft list` prints and the expressions it is compiled into (G2.8, see
/// [`crate::bytecode`]).
fn statements(
    table: Table,
    r: &FirewallRule,
    fam: Family,
    filled: &BTreeSet<&Name>,
    picks: (Pick, Pick),
) -> KernelRule {
    use crate::bytecode as bc;
    use crate::program::{Expr, MetaKey, NatKind};
    let m = &r.matchers;
    let mut b = bc::RuleBuild::default();
    match fam {
        Family::Ipv4 => b.push(
            "meta nfproto ipv4",
            bc::meta_cmp(MetaKey::NfProto, true, vec![bc::NFPROTO_IPV4]),
        ),
        Family::Ipv6 => b.push(
            "meta nfproto ipv6",
            bc::meta_cmp(MetaKey::NfProto, true, vec![bc::NFPROTO_IPV6]),
        ),
        Family::Both => {}
    }
    let v6 = fam == Family::Ipv6;
    let ip = if v6 { "ip6" } else { "ip" };
    for (out, name, list) in [
        (false, &m.in_interface, &m.in_interface_list),
        (true, &m.out_interface, &m.out_interface_list),
    ] {
        let kw = if out { "oifname" } else { "iifname" };
        let key = if out {
            MetaKey::OifName
        } else {
            MetaKey::IifName
        };
        if let Some(i) = name {
            b.push(
                format!("{kw} {}{}", op(i), quoted(i.value.as_str())),
                bc::meta_cmp(key, !i.not, bc::ifname_bytes(i.value.as_str())),
            );
        }
        if let Some(l) = list {
            let set = set_if(&l.value);
            b.push(
                format!("{kw} {}@{set}", op(l)),
                bc::ifname_set_exprs(out, l.not, &set),
            );
        }
    }
    for (src, a) in [(true, &m.src_address), (false, &m.dst_address)] {
        let Some(a) = a else { continue };
        let dir = if src { "saddr" } else { "daddr" };
        b.need_nfproto(a.value.family() == Family::Ipv6);
        b.push(
            format!("{ip} {dir} {}{}", op(a), addr_text(&a.value)),
            bc::addr_exprs(src, a.not, &a.value),
        );
    }
    let set = |l: &Name| {
        if v6 { set_v6(l) } else { set_v4(l) }
    };
    let dyn_set = |l: &Name| {
        if v6 { dyn_v6(l) } else { dyn_v4(l) }
    };
    for (src, list, pick) in [
        (true, &m.src_address_list, picks.0),
        (false, &m.dst_address_list, picks.1),
    ] {
        let Some(l) = list else { continue };
        let dir = if src { "saddr" } else { "daddr" };
        b.need_nfproto(v6);
        let lookup = |b: &mut bc::RuleBuild, not: bool, s: String| {
            b.push(
                format!("{ip} {dir} {}@{s}", if not { "!= " } else { "" }),
                bc::addr_set_exprs(v6, src, not, &s),
            );
        };
        if !filled.contains(&l.value) {
            lookup(&mut b, l.not, set(&l.value));
        } else if l.not {
            lookup(&mut b, true, set(&l.value));
            lookup(&mut b, true, dyn_set(&l.value));
        } else if pick == Pick::Static {
            lookup(&mut b, false, set(&l.value));
        } else {
            lookup(&mut b, false, dyn_set(&l.value));
            lookup(&mut b, true, set(&l.value));
        }
    }
    if let Some(p) = &m.protocol {
        b.push(
            format!("meta l4proto {}{}", op(p), proto_text(p.value)),
            bc::meta_cmp(MetaKey::L4Proto, !p.not, vec![p.value.0]),
        );
    }
    // nft merges `th sport X th dport Y` into one load.
    let merged = match (&m.src_port, &m.dst_port) {
        (Some(s), Some(d)) => bc::single_port(s).zip(bc::single_port(d)),
        _ => None,
    };
    if let (Some((sp, dp)), Some(s), Some(d)) = (merged, &m.src_port, &m.dst_port) {
        b.push(
            format!(
                "th sport {}{} th dport {}{}",
                op(s),
                ports_text(&s.value),
                op(d),
                ports_text(&d.value)
            ),
            bc::ports_merged(sp, dp),
        );
    } else {
        for (src, p) in [(true, &m.src_port), (false, &m.dst_port)] {
            let Some(p) = p else { continue };
            b.push(
                format!(
                    "th {} {}{}",
                    if src { "sport" } else { "dport" },
                    op(p),
                    ports_text(&p.value)
                ),
                bc::port_exprs(src, p.not, &p.value),
            );
        }
    }
    if let Some(i) = &m.icmp_options {
        let icmp6 = m
            .protocol
            .as_ref()
            .is_some_and(|p| p.value == Protocol::ICMPV6);
        let kw = if icmp6 { "icmpv6" } else { "icmp" };
        b.need_l4proto(if icmp6 { 58 } else { 1 });
        let mut text = format!("{kw} type {}", i.kind);
        if let Some(c) = i.code {
            let _ = write!(text, " {kw} code {c}");
        }
        b.push(text, bc::icmp_exprs(i.kind, i.code));
    }
    if let Some(f) = &m.connection_state {
        b.push(states_text(f), bc::ct_state_exprs(f));
    }
    if let Some(f) = &m.connection_nat_state {
        b.push(nat_states_text(f), bc::ct_nat_exprs(f));
    }
    if let Some(n) = &m.connection_mark {
        let v = mark_value(MarkKind::Connection, &n.value);
        b.push(
            format!("ct mark {}0x{v:08x}", op(n)),
            bc::ct_mark_match(n.not, v),
        );
    }
    for (n, mask, kind) in [
        (&m.packet_mark, 0x0000_ffff_u32, MarkKind::Packet),
        (&m.routing_mark, 0xffff_0000, MarkKind::Routing),
    ] {
        let Some(n) = n else { continue };
        let v = mark_value(kind, &n.value);
        b.push(
            format!(
                "meta mark & 0x{mask:08x} {} 0x{v:08x}",
                if n.not { "!=" } else { "==" }
            ),
            bc::mark_match(mask, v, !n.not),
        );
    }
    if let Some(l) = &m.limit {
        b.push(
            format!(
                "limit rate {}/{} burst {} packets",
                l.count,
                l.period.name(),
                l.burst
            ),
            vec![Expr::Limit {
                rate: u64::from(l.count),
                unit_secs: u64::from(l.period.secs()),
                burst: l.burst,
            }],
        );
    }
    b.push("counter", vec![Expr::Counter]);
    let then_accept = |pass: bool| {
        if pass {
            (String::new(), Vec::new())
        } else {
            (" accept".to_owned(), vec![Expr::Accept])
        }
    };
    let nat_kw = |t: &NatTarget| {
        if t.family() == Family::Ipv6 {
            "ip6"
        } else {
            "ip"
        }
    };
    let reject = |code: u8, name: &str| {
        (
            format!("reject with icmpx type {name}"),
            vec![Expr::Reject {
                kind: bc::REJECT_ICMPX,
                code,
            }],
        )
    };
    let (act, exprs): (String, Vec<Expr>) = match &r.action {
        Action::Accept => ("accept".into(), vec![Expr::Accept]),
        Action::Drop => ("drop".into(), vec![Expr::Drop]),
        Action::Reject { reject_with } => match reject_with {
            RejectWith::TcpReset => {
                b.need_l4proto(6);
                (
                    "reject with tcp reset".into(),
                    vec![Expr::Reject {
                        kind: bc::REJECT_TCP_RST,
                        code: 0,
                    }],
                )
            }
            RejectWith::IcmpNoRoute => reject(bc::ICMPX_NO_ROUTE, "no-route"),
            RejectWith::IcmpAdminProhibited => {
                reject(bc::ICMPX_ADMIN_PROHIBITED, "admin-prohibited")
            }
            RejectWith::IcmpAddressUnreachable => {
                reject(bc::ICMPX_HOST_UNREACH, "host-unreachable")
            }
            RejectWith::IcmpPortUnreachable => reject(bc::ICMPX_PORT_UNREACH, "port-unreachable"),
        },
        Action::Jump { jump_target } => {
            let chain = chain_name(table, jump_target.as_str());
            (format!("jump {chain}"), vec![Expr::Jump { chain }])
        }
        Action::Return => ("return".into(), vec![Expr::Return]),
        Action::Log { log_prefix } if log_prefix.is_empty() => {
            ("log".into(), vec![Expr::Log { prefix: None }])
        }
        Action::Log { log_prefix } => {
            let q = quoted(log_prefix);
            let prefix = q.trim_matches('"').to_owned();
            (
                format!("log prefix {q}"),
                vec![Expr::Log {
                    prefix: Some(prefix),
                }],
            )
        }
        Action::Passthrough => (String::new(), Vec::new()),
        // RouterOS: notrack ends the raw chain like accept.
        Action::Notrack => ("notrack accept".into(), vec![Expr::Notrack, Expr::Accept]),
        Action::Masquerade { to_ports } => (
            match to_ports {
                None => "masquerade".into(),
                Some(p) => format!("masquerade to :{p}"),
            },
            bc::masq_exprs(*to_ports),
        ),
        Action::SrcNat {
            to_addresses,
            to_ports,
        } => (
            format!(
                "snat {} to {}",
                nat_kw(to_addresses),
                nat_to(to_addresses, *to_ports)
            ),
            bc::nat_exprs(
                NatKind::Snat,
                to_addresses.first,
                to_addresses.last,
                *to_ports,
            ),
        ),
        Action::DstNat {
            to_addresses,
            to_ports,
        } => (
            format!(
                "dnat {} to {}",
                nat_kw(to_addresses),
                nat_to(to_addresses, *to_ports)
            ),
            bc::nat_exprs(
                NatKind::Dnat,
                to_addresses.first,
                to_addresses.last,
                *to_ports,
            ),
        ),
        Action::MarkConnection {
            new_connection_mark,
            passthrough,
        } => {
            let v = mark_value(MarkKind::Connection, new_connection_mark);
            let (t, mut e) = then_accept(*passthrough);
            let mut exprs = bc::ct_mark_set(v);
            exprs.append(&mut e);
            (format!("ct mark set 0x{v:08x}{t}"), exprs)
        }
        Action::MarkPacket {
            new_packet_mark,
            passthrough,
        } => {
            let v = mark_value(MarkKind::Packet, new_packet_mark);
            let (t, mut e) = then_accept(*passthrough);
            let mut exprs = bc::mark_set(0xffff_0000, v);
            exprs.append(&mut e);
            (
                format!("meta mark set meta mark & 0xffff0000 | 0x{v:08x}{t}"),
                exprs,
            )
        }
        Action::MarkRouting {
            new_routing_mark,
            passthrough,
        } => {
            let v = mark_value(MarkKind::Routing, new_routing_mark);
            let (t, mut e) = then_accept(*passthrough);
            let mut exprs = bc::mark_set(0x0000_ffff, v);
            exprs.append(&mut e);
            (
                format!("meta mark set meta mark & 0x0000ffff | 0x{v:08x}{t}"),
                exprs,
            )
        }
        Action::AddSrcToAddressList {
            address_list,
            address_list_timeout,
        }
        | Action::AddDstToAddressList {
            address_list,
            address_list_timeout,
        } => {
            let src = matches!(r.action, Action::AddSrcToAddressList { .. });
            let dir = if src { "saddr" } else { "daddr" };
            let timeout = address_list_timeout
                .map(|t| format!(" timeout {}s", t.secs()))
                .unwrap_or_default();
            let set = dyn_set(address_list);
            let mut exprs = bc::addr_set_exprs(v6, src, false, &set);
            exprs.pop();
            exprs.push(Expr::DynsetAdd {
                set: set.clone(),
                sreg_key: crate::program::REG_1,
                timeout_ms: address_list_timeout.map(|t| u64::from(t.secs()) * 1000),
            });
            (format!("add @{set} {{ {ip} {dir}{timeout} }}"), exprs)
        }
    };
    b.push(act, exprs);
    let tag = rule_tag(r.id);
    b.push(format!("comment {}", quoted(&tag)), Vec::new());
    let (text, exprs) = b.finish();
    KernelRule {
        text,
        exprs,
        comment: tag,
    }
}

/// One kernel rule of a firewall rule: what `nft list` prints, its
/// expressions and its comment (`cr:*N`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelRule {
    pub text: String,
    pub exprs: Vec<crate::program::Expr>,
    pub comment: String,
}

/// Kernel rules for `r`: one, or one per family when it uses address lists
/// and applies to both. Empty when it can never match (invalid families,
/// which the validator reports).
pub fn kernel_rules(table: Table, r: &FirewallRule, filled: &BTreeSet<&Name>) -> Vec<KernelRule> {
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

/// The base chain of `hook` named `prio` (nft's priority keywords).
fn base_chain(name: String, ty: &str, hook: &str, prio: &str) -> program::Chain {
    use program::{ChainType, Hook};
    let kind = match ty {
        "nat" => ChainType::Nat,
        "route" => ChainType::Route,
        _ => ChainType::Filter,
    };
    let hook = match hook {
        "prerouting" => Hook::Prerouting,
        "input" => Hook::Input,
        "forward" => Hook::Forward,
        "output" => Hook::Output,
        _ => Hook::Postrouting,
    };
    let priority = match prio {
        "raw" => -300,
        "mangle" => -150,
        "dstnat" => -100,
        "srcnat" => 100,
        _ => 0,
    };
    program::Chain {
        name,
        kind,
        hook,
        priority,
        priority_text: prio.to_owned(),
    }
}

fn regular_chain(name: String) -> program::Chain {
    program::Chain {
        name,
        kind: program::ChainType::Filter,
        hook: program::Hook::Regular,
        priority: 0,
        priority_text: String::new(),
    }
}

/// The body of `table inet corerouter`, or `None` when the config has no
/// firewall at all (no rules, no address-list entries, no dynamic entry from a command):
/// then the table should not exist.
pub fn render(cfg: &Config, dynamic: &[DynamicAddress]) -> Option<String> {
    build(cfg, dynamic).map(|(text, _)| text)
}

/// The same table as nf_tables objects (G2.8): what `hal-linux` sends over
/// nfnetlink. Its rules carry the text [`render`] prints.
pub fn program(cfg: &Config, dynamic: &[DynamicAddress]) -> Option<program::Table> {
    build(cfg, dynamic).map(|(_, t)| t)
}

/// [`render`] and [`program`] in one pass, so they cannot disagree.
pub fn build(cfg: &Config, dynamic: &[DynamicAddress]) -> Option<(String, program::Table)> {
    use program::{FwElement, FwSet, KeyKind};
    let fw = &cfg.ip.firewall;
    if fw.is_empty() && dynamic.iter().all(|d| d.added_by_rule) && !crate::notice::on(cfg) {
        return None;
    }
    let mut t = program::Table {
        family: program::Family::Inet,
        name: TABLE.to_owned(),
        ..program::Table::default()
    };
    let mut out = String::new();
    let _ = writeln!(out, "table inet {TABLE} {{");
    let filled = filled_lists(cfg);
    // Entries grouped by list once: filtering every entry for every list
    // was O(lists × entries) (65 536 entries over 500 lists).
    let mut statics: BTreeMap<&Name, Vec<&AddressListEntry>> = BTreeMap::new();
    for e in fw.address_lists.iter().filter(|e| !e.disabled) {
        statics.entry(&e.list).or_default().push(e);
    }
    let mut dynamics: BTreeMap<&Name, Vec<&DynamicAddress>> = BTreeMap::new();
    for d in dynamic {
        dynamics.entry(&d.list).or_default().push(d);
    }
    let none_s: Vec<&AddressListEntry> = Vec::new();
    let none_d: Vec<&DynamicAddress> = Vec::new();

    let notice_lists = crate::notice::lists(cfg);
    let mut lists = address_lists(cfg, dynamic);
    lists.extend(notice_lists.iter());
    for list in lists {
        let list_statics = statics.get(list).unwrap_or(&none_s);
        let list_dynamic = dynamics.get(list).unwrap_or(&none_d);
        for (fam, name, ty, key) in [
            (Family::Ipv4, set_v4(list), "ipv4_addr", KeyKind::Ipv4),
            (Family::Ipv6, set_v6(list), "ipv6_addr", KeyKind::Ipv6),
        ] {
            let st: Vec<&AddrMatch> = list_statics
                .iter()
                .filter(|e| e.address.family() == fam)
                .map(|e| &e.address)
                .collect();
            // Entries a rule added go back to the dynamic set below (and
            // are dropped once no rule fills the list).
            let timed: Vec<(&AddrMatch, u64)> = list_dynamic
                .iter()
                .filter(|d| d.address.family() == fam)
                .filter(|d| !d.added_by_rule)
                .map(|d| (&d.address, d.timeout_secs.max(1)))
                .collect();
            let mut items: Vec<String> = st.iter().map(|a| addr_text(a)).collect();
            items.extend(
                timed
                    .iter()
                    .map(|(a, s)| format!("{} timeout {s}s", addr_text(a))),
            );
            let _ = write!(
                out,
                "\tset {name} {{\n\t\ttype {ty}\n\t\tflags interval, timeout\n\t\tauto-merge\n{}\t}}\n",
                elements(&items)
            );
            t.fw_sets.push(FwSet {
                name,
                key,
                interval: true,
                timeout: true,
                dynamic: false,
                size: None,
                auto_merge: true,
                elements: crate::bytecode::interval_elements(&st, &timed),
            });
        }
        if !filled.contains(list) {
            continue;
        }
        for (fam, name, ty, key) in [
            (Family::Ipv4, dyn_v4(list), "ipv4_addr", KeyKind::Ipv4),
            (Family::Ipv6, dyn_v6(list), "ipv6_addr", KeyKind::Ipv6),
        ] {
            // Only single addresses fit a plain set.
            let addrs: Vec<(std::net::IpAddr, u64)> = list_dynamic
                .iter()
                .filter(|d| d.added_by_rule && d.address.family() == fam)
                .filter_map(|d| match d.address {
                    AddrMatch::Net(n) if n.prefix_len() == n.max_prefix_len() => {
                        Some((n.addr(), d.timeout_secs))
                    }
                    _ => None,
                })
                .collect();
            let items: Vec<String> = addrs
                .iter()
                .map(|(a, secs)| {
                    if *secs > 0 {
                        format!("{a} timeout {secs}s")
                    } else {
                        a.to_string()
                    }
                })
                .collect();
            let _ = write!(
                out,
                "\tset {name} {{\n\t\ttype {ty}\n\t\tsize {DYNAMIC_SET_SIZE}\n\t\tflags dynamic, timeout\n{}\t}}\n",
                elements(&items)
            );
            let mut elems: Vec<FwElement> = addrs
                .iter()
                .map(|(a, secs)| FwElement {
                    key: match a {
                        std::net::IpAddr::V4(v) => v.octets().to_vec(),
                        std::net::IpAddr::V6(v) => v.octets().to_vec(),
                    },
                    last: None,
                    timeout_ms: (*secs > 0).then(|| secs.saturating_mul(1000)),
                })
                .collect();
            elems.sort();
            elems.dedup_by(|a, b| a.key == b.key);
            t.fw_sets.push(FwSet {
                name,
                key,
                interval: false,
                timeout: true,
                dynamic: true,
                size: Some(DYNAMIC_SET_SIZE),
                auto_merge: false,
                elements: elems,
            });
        }
    }
    for list in &cfg.interface_lists.lists {
        let names: BTreeSet<&str> = cfg
            .interface_lists
            .interfaces_of(list.name.as_str())
            .map(|i: &IfName| i.as_str())
            .collect();
        let items: Vec<String> = names.iter().map(|n| quoted(n)).collect();
        let _ = write!(
            out,
            "\tset {} {{\n\t\ttype ifname\n{}\t}}\n",
            set_if(&list.name),
            elements(&items)
        );
        t.fw_sets.push(FwSet {
            name: set_if(&list.name),
            key: KeyKind::IfName,
            interval: false,
            timeout: false,
            dynamic: false,
            size: None,
            auto_merge: false,
            elements: names
                .iter()
                .map(|n| FwElement {
                    key: crate::bytecode::ifname_bytes(n),
                    last: None,
                    timeout_ms: None,
                })
                .collect(),
        });
    }

    // Port lists: one shared set per distinct list (see
    // `bytecode::port_set_name`).
    let mut port_sets: BTreeMap<String, FwSet> = BTreeMap::new();
    for table in Table::ALL {
        for r in fw.rules(table).iter().filter(|r| !r.disabled && !r.section) {
            for p in [&r.matchers.src_port, &r.matchers.dst_port]
                .into_iter()
                .flatten()
            {
                if p.value.0.len() > 1 {
                    let s = crate::bytecode::port_set(&p.value);
                    port_sets.entry(s.name.clone()).or_insert(s);
                }
            }
        }
    }
    for s in port_sets.into_values() {
        let items: Vec<String> = crate::bytecode::merged_ports_of(&s)
            .iter()
            .map(PortRange::to_string)
            .collect();
        let _ = write!(
            out,
            "\tset {} {{\n\t\ttype inet_service\n\t\tflags interval\n{}\t}}\n",
            s.name,
            elements(&items)
        );
        t.fw_sets.push(s);
    }

    for table in Table::ALL {
        let rules = fw.rules(table);
        // Live rules by chain, in order (one pass, not one per chain).
        let mut live: BTreeMap<&str, Vec<&FirewallRule>> = BTreeMap::new();
        for r in rules.iter().filter(|r| !r.disabled && !r.section) {
            live.entry(r.chain.as_str()).or_default().push(r);
        }
        let mut chains: Vec<String> = table
            .builtin_chains()
            .iter()
            .filter(|c| live.contains_key(**c))
            .map(|c| (*c).to_owned())
            .collect();
        chains.extend(
            graph::custom_chains(table, rules)
                .into_iter()
                .map(|n| n.as_str().to_owned()),
        );
        for chain in chains {
            let kname = chain_name(table, &chain);
            let _ = writeln!(out, "\tchain {kname} {{");
            if let Some((ty, hook, prio)) = base_hook(table, &chain) {
                let _ = writeln!(
                    out,
                    "\t\ttype {ty} hook {hook} priority {prio}; policy accept;"
                );
                t.chains.push(base_chain(kname.clone(), ty, hook, prio));
            } else {
                t.chains.push(regular_chain(kname.clone()));
            }
            for r in live.get(chain.as_str()).into_iter().flatten() {
                for k in kernel_rules(table, r, &filled) {
                    let _ = writeln!(out, "\t\t{}", k.text);
                    t.rules.push(program::Rule {
                        chain: kname.clone(),
                        exprs: k.exprs,
                        text: k.text,
                        nft: None,
                        comment: Some(k.comment),
                    });
                }
            }
            let _ = writeln!(out, "\t}}");
        }
    }
    crate::notice::render(cfg, &mut out, &mut t);
    let _ = writeln!(out, "}}");
    Some((out, t))
}

/// Whether going from `from` to `to` changes the ruleset. `render` reads
/// only the firewall, the interface lists and the subscriber notices, so a commit that touches
/// neither does not render at all (both configs were rendered on every
/// commit, ~1 ms per 1000 rules).
pub fn changed(from: &Config, to: &Config) -> bool {
    inputs_changed(from, to) && render(from, &[]) != render(to, &[])
}

/// Whether anything [`render`] reads differs (a struct comparison, no
/// render): `hal-linux` diffs the two programs itself (G2.8).
pub fn inputs_changed(from: &Config, to: &Config) -> bool {
    from.ip.firewall != to.ip.firewall
        || from.interface_lists != to.interface_lists
        || from.ip.subscriber_notice != to.ip.subscriber_notice
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_rules_map_back_to_ours() {
        let id = ItemId(0x16);
        assert_eq!(
            rule_of("raw_prerouting", Some(&rule_tag(id))),
            Some((Table::Raw, id))
        );
        assert_eq!(
            rule_of("filter_my-chain", Some("cr:*1")),
            Some((Table::Filter, ItemId(1)))
        );
        assert_eq!(rule_of("notice_dstnat", Some("cr:*1")), None);
        assert_eq!(rule_of("filter_input", Some("docker")), None);
        assert_eq!(rule_of("filter_input", None), None);
        assert_eq!(table_of_chain("nat_srcnat"), Some((Table::Nat, "srcnat")));
    }
}

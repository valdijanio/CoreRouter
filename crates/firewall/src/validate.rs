//! What makes a firewall config wrong. [`rule_issues`] judges one rule in its
//! config (the commands report its first finding as a parameter error);
//! [`validate`] runs it on every rule and adds the whole-config checks.

use std::collections::{BTreeMap, BTreeSet};

use corerouter_model::firewall::{
    Action, Family, FirewallRule, Name, Protocol, RejectWith, Table, Zone,
};
use corerouter_model::interface_list::RESERVED;
use corerouter_model::{Config, Issue};

use crate::graph;
use crate::nft::{MarkKind, mark_value};

/// Hostile-input bounds (**estimado**: far above what a router needs).
pub const MAX_RULES: usize = 4096;
/// G4.10b: 262 144, room for every subscriber of a big ISP in a notice
/// list (100 000 load in 0,24 s and cost nothing per packet, **medido**).
pub const MAX_ADDRESS_LIST_ENTRIES: usize = 262_144;
pub const MAX_INTERFACE_LISTS: usize = 256;
pub const MAX_INTERFACE_LIST_MEMBERS: usize = 4096;
pub const MAX_LOG_PREFIX: usize = 64;
/// The kernel keeps 128 bytes of comment; titles longer than that are
/// still fine because comments never reach the kernel.
pub const MAX_COMMENT: usize = 256;
/// Zone-matrix cells: (256 lists + router)² would be far more than a
/// screen can show (**estimado**).
pub const MAX_ZONE_CELLS: usize = 1024;

/// Actions allowed in `table` (before looking at the chain).
fn table_allows(table: Table, action: &Action) -> bool {
    let common = matches!(
        action,
        Action::Accept
            | Action::Jump { .. }
            | Action::Return
            | Action::Log { .. }
            | Action::Passthrough
            | Action::AddSrcToAddressList { .. }
            | Action::AddDstToAddressList { .. }
    );
    common
        || match table {
            Table::Filter => matches!(action, Action::Drop | Action::Reject { .. }),
            Table::Nat => matches!(
                action,
                Action::Masquerade { .. } | Action::SrcNat { .. } | Action::DstNat { .. }
            ),
            Table::Mangle => matches!(
                action,
                Action::MarkConnection { .. }
                    | Action::MarkPacket { .. }
                    | Action::MarkRouting { .. }
            ),
            Table::Raw => matches!(action, Action::Drop | Action::Notrack),
        }
}

/// The built-in chains an action may run from, if it is restricted.
fn chain_limit(action: &Action) -> Option<&'static [&'static str]> {
    match action {
        Action::Masquerade { .. } | Action::SrcNat { .. } => Some(&["srcnat"]),
        Action::DstNat { .. } => Some(&["dstnat"]),
        // The kernel routes again after a mark only there.
        Action::MarkRouting { .. } => Some(&["prerouting", "output"]),
        _ => None,
    }
}

/// Built-in chains where a packet has no input interface yet / no output
/// interface yet (a matcher on it could never match).
const NO_IN: &[&str] = &["output"];
const NO_OUT: &[&str] = &["input", "prerouting", "dstnat"];

fn needs_ports(field: &'static str, r: &FirewallRule) -> Option<(&'static str, String)> {
    let proto = r.matchers.protocol.as_ref();
    match proto {
        Some(p) if !p.not && p.value.has_ports() => None,
        _ => Some((
            field,
            "needs protocol tcp, udp, sctp or udp-lite (only they have ports)".into(),
        )),
    }
}

/// The families a rule can match, or the field that rules out every family.
pub fn family(r: &FirewallRule) -> Result<Family, (&'static str, String)> {
    let mut fam = r.family;
    let m = &r.matchers;
    let mut narrow = |field: &'static str, f: Family| -> Result<(), (&'static str, String)> {
        fam = fam.and(f).ok_or_else(|| {
            (
                field,
                format!(
                    "is {} but the rule is for {} only",
                    family_label(f),
                    family_label(fam)
                ),
            )
        })?;
        Ok(())
    };
    if let Some(a) = &m.src_address {
        narrow("src_address", a.value.family())?;
    }
    if let Some(a) = &m.dst_address {
        narrow("dst_address", a.value.family())?;
    }
    if let Some(p) = m.protocol.as_ref().filter(|p| !p.not) {
        if p.value == Protocol::ICMP {
            narrow("protocol", Family::Ipv4)?;
        } else if p.value == Protocol::ICMPV6 {
            narrow("protocol", Family::Ipv6)?;
        }
    }
    match &r.action {
        Action::SrcNat { to_addresses, .. } | Action::DstNat { to_addresses, .. } => {
            narrow("to_addresses", to_addresses.family())?;
        }
        _ => {}
    }
    Ok(fam)
}

fn family_label(f: Family) -> &'static str {
    match f {
        Family::Both => "IPv4 and IPv6",
        Family::Ipv4 => "IPv4",
        Family::Ipv6 => "IPv6",
    }
}

fn clean_text(s: &str) -> bool {
    s.chars()
        .all(|c| (' '..='~').contains(&c) && c != '"' && c != '\\')
}

/// Problems with rule `r` of `table` in `cfg`, as (field, message). The
/// rule may or may not be in `cfg` yet (the commands check before adding).
pub fn rule_issues(cfg: &Config, table: Table, r: &FirewallRule) -> Vec<(&'static str, String)> {
    // The table as it would be with `r` (replacing the rule with its id).
    let rules = cfg.ip.firewall.rules(table);
    let with_r = rules
        .iter()
        .filter(|o| o.id != r.id)
        .chain(std::iter::once(r));
    let edges = graph::edges(with_r);
    let roots = graph::roots_in(table, &edges, r.chain.as_str());
    issues_in(cfg, table, r, &roots)
}

/// [`rule_issues`] of every rule of `table` in `cfg`, in table order. The
/// jumps and each chain's roots are worked out once for the table: per
/// rule, a listing of 10 000 rules built the graph 10 000 times (G0.31).
pub fn table_issues(cfg: &Config, table: Table) -> Vec<Vec<(&'static str, String)>> {
    let rules = cfg.ip.firewall.rules(table);
    let edges = graph::edges(rules);
    let mut roots: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    rules
        .iter()
        .map(|r| {
            let chain = r.chain.as_str();
            let reach = roots
                .entry(chain)
                .or_insert_with(|| graph::roots_in(table, &edges, chain));
            issues_in(cfg, table, r, reach)
        })
        .collect()
}

/// [`rule_issues`] with the built-in chains that reach `r`'s chain known.
fn issues_in(
    cfg: &Config,
    table: Table,
    r: &FirewallRule,
    roots: &BTreeSet<&str>,
) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    if r.comment.chars().count() > MAX_COMMENT {
        out.push(("comment", format!("at most {MAX_COMMENT} characters")));
    }
    if r.comment.chars().any(char::is_control) {
        out.push(("comment", "control characters are not allowed".into()));
    }
    if r.section {
        if r.comment.trim().is_empty() {
            out.push(("section", "a section needs a title".into()));
        }
        if !r.matchers.is_empty() || r.action != Action::Accept {
            out.push((
                "section",
                "a section header matches nothing: no matchers or action".into(),
            ));
        }
        return out;
    }

    // Where the rule runs: its chain, or the built-in chains jumping to it.
    let chain = r.chain.as_str();
    let builtin = graph::is_builtin(table, chain);
    if !builtin
        && table
            .builtin_chains()
            .iter()
            .any(|c| c.eq_ignore_ascii_case(chain))
    {
        out.push((
            "chain",
            format!(
                "built-in chain names are lowercase: did you mean {}?",
                chain.to_lowercase()
            ),
        ));
    }

    // Action.
    let action = &r.action;
    if !table_allows(table, action) {
        out.push((
            "action",
            format!("{} is not a {} action", action.name(), table.name()),
        ));
    } else if let Some(allowed) = chain_limit(action) {
        let ok = if builtin {
            allowed.contains(&chain)
        } else {
            // A custom chain: every built-in chain that reaches it must allow it.
            roots.iter().all(|c| allowed.contains(c))
        };
        if !ok {
            out.push((
                "action",
                format!(
                    "{} works only in chain {}",
                    action.name(),
                    allowed.join(" or ")
                ),
            ));
        }
    }
    match action {
        Action::Jump { jump_target } => {
            if graph::is_builtin(table, jump_target.as_str()) {
                out.push((
                    "jump_target",
                    format!("{jump_target} is a built-in chain; jump to a chain of your own"),
                ));
            } else if *jump_target == r.chain {
                out.push(("jump_target", "a chain cannot jump to itself".into()));
            }
        }
        Action::Log { log_prefix } => {
            if log_prefix.len() > MAX_LOG_PREFIX || !clean_text(log_prefix) {
                out.push((
                    "log_prefix",
                    format!("up to {MAX_LOG_PREFIX} printable ASCII characters, without \" or \\"),
                ));
            }
        }
        Action::Reject {
            reject_with: RejectWith::TcpReset,
        } => {
            let tcp = r
                .matchers
                .protocol
                .as_ref()
                .is_some_and(|p| !p.not && p.value == Protocol::TCP);
            if !tcp {
                out.push(("reject_with", "tcp-reset needs protocol=tcp".into()));
            }
        }
        Action::Masquerade { to_ports: Some(_) }
        | Action::SrcNat {
            to_ports: Some(_), ..
        }
        | Action::DstNat {
            to_ports: Some(_), ..
        } => {
            if let Some(i) = needs_ports("to_ports", r) {
                out.push(i);
            }
        }
        _ => {}
    }

    // Matchers.
    let m = &r.matchers;
    if m.src_port.is_some() {
        out.extend(needs_ports("src_port", r));
    }
    if m.dst_port.is_some() {
        out.extend(needs_ports("dst_port", r));
    }
    if m.icmp_options.is_some() {
        let icmp = m
            .protocol
            .as_ref()
            .is_some_and(|p| !p.not && (p.value == Protocol::ICMP || p.value == Protocol::ICMPV6));
        if !icmp {
            out.push((
                "icmp_options",
                "needs protocol=icmp or protocol=icmpv6".into(),
            ));
        }
    }
    if let Err(e) = family(r) {
        out.push(e);
    }
    // Raw runs before connection tracking: nothing about the connection
    // is known yet (RouterOS has no such matchers in raw either).
    if table == Table::Raw {
        for (field, set) in [
            ("connection_state", m.connection_state.is_some()),
            ("connection_nat_state", m.connection_nat_state.is_some()),
            ("connection_mark", m.connection_mark.is_some()),
            ("routing_mark", m.routing_mark.is_some()),
        ] {
            if set {
                out.push((
                    field,
                    "raw runs before connection tracking: use it in filter or mangle".into(),
                ));
            }
        }
    }
    let in_any = m.in_interface.is_some() || m.in_interface_list.is_some();
    let out_any = m.out_interface.is_some() || m.out_interface_list.is_some();
    if in_any && !roots.is_empty() && roots.iter().all(|c| NO_IN.contains(c)) {
        out.push((
            if m.in_interface.is_some() {
                "in_interface"
            } else {
                "in_interface_list"
            },
            "locally generated packets (chain output) have no input interface".into(),
        ));
    }
    if out_any && !roots.is_empty() && roots.iter().all(|c| NO_OUT.contains(c)) {
        out.push((
            if m.out_interface.is_some() {
                "out_interface"
            } else {
                "out_interface_list"
            },
            format!(
                "chain {} runs before routing: there is no output interface yet",
                roots.iter().copied().collect::<Vec<_>>().join("/")
            ),
        ));
    }
    for (field, list) in [
        ("in_interface_list", &m.in_interface_list),
        ("out_interface_list", &m.out_interface_list),
    ] {
        if let Some(l) = list
            && cfg.interface_lists.get(l.value.as_str()).is_none()
        {
            out.push((
                field,
                format!(
                    "interface list '{}' does not exist (see interface.list.list)",
                    l.value
                ),
            ));
        }
    }
    out
}

/// Every problem in the firewall and interface lists of `cfg`.
pub fn validate(cfg: &Config) -> Vec<Issue> {
    let mut out = Vec::new();
    let fw = &cfg.ip.firewall;
    for table in Table::ALL {
        let rules = fw.rules(table);
        if rules.len() > MAX_RULES {
            out.push(Issue::new(
                format!("ip.firewall.{table}"),
                format!("at most {MAX_RULES} rules"),
            ));
        }
        let mut ids = BTreeSet::new();
        // Jumps and the roots of each chain once per table: O(N log N)
        // for the table instead of a copy and a graph per rule (audit-net).
        let edges = graph::edges(rules);
        let mut roots: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
        for r in rules {
            if !ids.insert(r.id) {
                out.push(Issue::new(
                    format!("ip.firewall.{table}[{}]", r.id),
                    "duplicate rule id",
                ));
            }
            let chain = r.chain.as_str();
            let reach = roots
                .entry(chain)
                .or_insert_with(|| graph::roots_in(table, &edges, chain));
            out.extend(
                issues_in(cfg, table, r, reach)
                    .into_iter()
                    .map(|(f, m)| Issue::new(format!("ip.firewall.{table}[{}].{f}", r.id), m)),
            );
        }
        if let Some(cycle) = graph::find_loop(rules) {
            out.push(Issue::new(
                format!("ip.firewall.{table}"),
                format!("jumps loop: {}", cycle.join(" → ")),
            ));
        }
    }
    out.extend(mark_collisions(cfg));
    out.extend(zone_issues(cfg));
    if fw.address_lists.len() > MAX_ADDRESS_LIST_ENTRIES {
        out.push(Issue::new(
            "ip.firewall.address_lists",
            format!("at most {MAX_ADDRESS_LIST_ENTRIES} entries"),
        ));
    }
    let lists = &cfg.interface_lists;
    if lists.lists.len() > MAX_INTERFACE_LISTS {
        out.push(Issue::new(
            "interface_lists",
            format!("at most {MAX_INTERFACE_LISTS} lists"),
        ));
    }
    if lists.members.len() > MAX_INTERFACE_LIST_MEMBERS {
        out.push(Issue::new(
            "interface_lists.members",
            format!("at most {MAX_INTERFACE_LIST_MEMBERS} members"),
        ));
    }
    let mut names = BTreeSet::new();
    for l in &lists.lists {
        if RESERVED.contains(&l.name.as_str()) {
            out.push(Issue::new(
                format!("interface_lists.{}", l.name),
                "reserved name (RouterOS built-in list)",
            ));
        }
        if !names.insert(l.name.as_str()) {
            out.push(Issue::new(
                format!("interface_lists.{}", l.name),
                "duplicate list name",
            ));
        }
    }
    let mut pairs = BTreeSet::new();
    for m in &lists.members {
        if lists.get(m.list.as_str()).is_none() {
            out.push(Issue::new(
                format!("interface_lists.members[{}].list", m.id),
                format!("interface list '{}' does not exist", m.list),
            ));
        }
        if !pairs.insert((m.list.as_str(), &m.interface)) {
            out.push(Issue::new(
                format!("interface_lists.members[{}]", m.id),
                format!("{} is already a member of {}", m.interface, m.list),
            ));
        }
    }
    out
}

/// The zone matrix: cells name existing lists, never the same zone twice,
/// each pair once.
fn zone_issues(cfg: &Config) -> Vec<Issue> {
    let zones = &cfg.ip.firewall.zones;
    let mut out = Vec::new();
    if zones.len() > MAX_ZONE_CELLS {
        out.push(Issue::new(
            "ip.firewall.zones",
            format!("at most {MAX_ZONE_CELLS} cells"),
        ));
    }
    let mut pairs = BTreeSet::new();
    for z in zones {
        let at = format!("ip.firewall.zones[{} → {}]", z.from, z.to);
        if z.from == z.to {
            out.push(Issue::new(&at, "a zone to itself is not a cell"));
        }
        if !pairs.insert((&z.from, &z.to)) {
            out.push(Issue::new(&at, "duplicate cell"));
        }
        for side in [&z.from, &z.to] {
            if let Zone::List(l) = side
                && cfg.interface_lists.get(l.as_str()).is_none()
            {
                out.push(Issue::new(
                    &at,
                    format!("interface list '{l}' does not exist"),
                ));
            }
        }
    }
    out
}

/// Marks are names; the kernel wants numbers. Two names that hash to the
/// same number would mix two marks, so that is refused.
fn mark_collisions(cfg: &Config) -> Vec<Issue> {
    let mut seen: BTreeMap<(MarkKind, u32), &Name> = BTreeMap::new();
    let mut out = Vec::new();
    let fw = &cfg.ip.firewall;
    for table in Table::ALL {
        for r in fw.rules(table) {
            let m = &r.matchers;
            let mut names: Vec<(MarkKind, &Name)> = Vec::new();
            if let Some(n) = &m.connection_mark {
                names.push((MarkKind::Connection, &n.value));
            }
            if let Some(n) = &m.packet_mark {
                names.push((MarkKind::Packet, &n.value));
            }
            if let Some(n) = &m.routing_mark {
                names.push((MarkKind::Routing, &n.value));
            }
            match &r.action {
                Action::MarkConnection {
                    new_connection_mark,
                    ..
                } => names.push((MarkKind::Connection, new_connection_mark)),
                Action::MarkPacket {
                    new_packet_mark, ..
                } => names.push((MarkKind::Packet, new_packet_mark)),
                Action::MarkRouting {
                    new_routing_mark, ..
                } => names.push((MarkKind::Routing, new_routing_mark)),
                _ => {}
            }
            for (kind, name) in names {
                let key = (kind, mark_value(kind, name));
                match seen.get(&key) {
                    Some(other) if *other != name => out.push(Issue::new(
                        format!("ip.firewall.{table}[{}]", r.id),
                        format!(
                            "mark names '{other}' and '{name}' map to the same kernel mark; \
                             rename one"
                        ),
                    )),
                    Some(_) => {}
                    None => {
                        seen.insert(key, name);
                    }
                }
            }
        }
    }
    out
}

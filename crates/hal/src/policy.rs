//! G1.27e: what `/routing rule`, the mangle routing marks and the VRFs put in
//! the kernel's rule list, and how a packet walks that list. The Linux
//! backend writes [`expected_rules`] (`FRA_*`); the virtual lab and
//! `ip.route.lookup` walk it with [`walk`], so the three cannot disagree.
//!
//! The list, in the kernel's order (`fib_rules_lookup` walks it linearly by
//! priority, a miss returns `-EAGAIN` and the next rule goes on):
//!
//! | priority | rule | RouterOS v7 stage |
//! |---|---|---|
//! | 0 | `local` table (kernel) | `local` |
//! | 100..=999 | one per routing mark of the mangle that names a table | `mangle` |
//! | 1000 | `l3mdev` (the kernel's VRF driver adds it) | `vrf-lookup` |
//! | 1001 | `l3mdev unreachable` | `vrf-unreach` |
//! | 2000.. | `/routing rule`, two priorities each | `user` |
//! | 32766, 32767 | `main`, `default` (kernel) | `main` |
//!
//! RouterOS looks at the mangle before `local`, and a forum note on 7.22
//! warns that a marked packet to the router itself then misses `input`.
//! Keeping `local` first avoids it and needs no change in the kernel's rule 0.
//!
//! A `/routing rule` keeps its two priorities whether it is enabled or not,
//! so disabling one or changing its action touches only that one.
//! `lookup-only-in-table` is `lookup` plus an `unreachable` right after it:
//! in the kernel a miss always goes on to the next rule.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use corerouter_firewall::nft::{MarkKind, mark_value};
use corerouter_model::firewall::{Action, Name};
use corerouter_model::policy_rule::{RoutingRule, RuleAction};
use corerouter_model::route::{self, MAIN_TABLE_ID};
use corerouter_model::{Config, IfName, InterfaceKind, RoutingTable};
use ipnet::IpNet;
use serde::Serialize;

/// `FRA_PROTOCOL` of the rules CoreRouter writes: how it tells its own from
/// another program's (never removed). iproute2's `rt_protos` leaves it free.
pub const RULE_PROTOCOL: u8 = 200;
/// The routing mark's bits in the packet mark (`corerouter_firewall::nft`).
pub const ROUTING_MARK_MASK: u32 = 0xffff_0000;
pub const FIRST_MARK_PREF: u32 = 100;
pub const LAST_MARK_PREF: u32 = 999;
/// `FIB_RULE_PREF` of the kernel's VRF driver.
pub const L3MDEV_PREF: u32 = 1000;
pub const VRF_UNREACH_PREF: u32 = 1001;
pub const FIRST_RULE_PREF: u32 = 2000;
pub const MAIN_PREF: u32 = 32766;
pub const DEFAULT_PREF: u32 = 32767;

/// The kernel's action of a rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum KernelRuleAction {
    Table(u32),
    Blackhole,
    Unreachable,
    /// Another program's (`goto`, `nop`, `prohibit`): read, never written.
    Other(u8),
}

/// One rule as the kernel holds it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct KernelRule {
    pub pref: u32,
    pub v6: bool,
    pub src: Option<IpNet>,
    pub dst: Option<IpNet>,
    pub iif: Option<IfName>,
    /// Compared under [`ROUTING_MARK_MASK`].
    pub mark: Option<u32>,
    pub action: KernelRuleAction,
    /// `FRA_SUPPRESS_PREFIXLEN`.
    pub suppress: Option<u8>,
    pub l3mdev: bool,
}

impl fmt::Display for KernelRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "rule {}", self.pref)?;
        if self.v6 {
            f.write_str(" ipv6")?;
        }
        if let Some(s) = self.src {
            write!(f, " from {s}")?;
        }
        if let Some(d) = self.dst {
            write!(f, " to {d}")?;
        }
        if let Some(i) = &self.iif {
            write!(f, " iif {i}")?;
        }
        if let Some(m) = self.mark {
            write!(f, " fwmark {m:#x}/{ROUTING_MARK_MASK:#x}")?;
        }
        if self.l3mdev {
            f.write_str(" l3mdev")?;
        }
        match self.action {
            KernelRuleAction::Table(t) => write!(f, " lookup {t}")?,
            KernelRuleAction::Blackhole => f.write_str(" blackhole")?,
            KernelRuleAction::Unreachable => f.write_str(" unreachable")?,
            KernelRuleAction::Other(code) => write!(f, " action {code}")?,
        }
        if let Some(s) = self.suppress {
            write!(f, " suppress_prefixlength {s}")?;
        }
        Ok(())
    }
}

/// Who wrote a rule of the kernel's list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleOwner {
    /// `local`, `main`, `default`, the VRF driver's `l3mdev`.
    Kernel,
    Corerouter,
    /// Another program or `ip rule`: read, never changed.
    Foreign,
}

/// One row of the kernel's whole list (`routing.rule.kernel`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KernelRuleRow {
    pub rule: KernelRule,
    pub owner: RuleOwner,
    /// `FRA_PROTOCOL`.
    pub protocol: u8,
}

/// Priorities of `/routing rule` at position `pos`.
pub fn rule_pref(pos: usize) -> u32 {
    let pos = u32::try_from(pos).unwrap_or(u32::MAX / 4);
    FIRST_RULE_PREF.saturating_add(pos.saturating_mul(2))
}

/// The position in `/routing rule` of a priority [`rule_pref`] gave.
pub fn pos_of_pref(pref: u32) -> Option<usize> {
    let off = pref.checked_sub(FIRST_RULE_PREF)?;
    if pref >= MAIN_PREF {
        return None;
    }
    usize::try_from(off / 2).ok()
}

/// A prefix the kernel matches with: truncated, and none for length 0 (it
/// neither keeps nor reports `FRA_SRC` of length 0).
fn selector(net: Option<IpNet>) -> Option<IpNet> {
    net.map(|n| n.trunc()).filter(|n| n.prefix_len() > 0)
}

/// What rule `r` at position `pos` becomes.
fn kernel_rules_of(cfg: &Config, r: &RoutingRule, pos: usize, out: &mut BTreeSet<KernelRule>) {
    if r.disabled {
        return;
    }
    let pref = rule_pref(pos);
    let families: &[bool] = match r.is_v6() {
        Some(true) => &[true],
        Some(false) => &[false],
        None => &[false, true],
    };
    let mark = r
        .routing_mark
        .as_ref()
        .map(|m| mark_value(MarkKind::Routing, m));
    let table = route::table_id(cfg, &r.table);
    for &v6 in families {
        let one = |pref, action, suppress| KernelRule {
            pref,
            v6,
            src: selector(r.src_address),
            dst: selector(r.dst_address),
            iif: r.interface.clone(),
            mark,
            action,
            suppress,
            l3mdev: false,
        };
        match (r.action, table) {
            (RuleAction::Lookup, Some(t)) => {
                out.insert(one(pref, KernelRuleAction::Table(t), r.min_prefix));
            }
            (RuleAction::LookupOnlyInTable, Some(t)) => {
                out.insert(one(pref, KernelRuleAction::Table(t), r.min_prefix));
                out.insert(one(pref + 1, KernelRuleAction::Unreachable, None));
            }
            // An unknown table never passes validation; a config with one
            // falls through to the next rule rather than lose the others.
            (RuleAction::Lookup | RuleAction::LookupOnlyInTable, None) => {}
            (RuleAction::Drop, _) => {
                out.insert(one(pref, KernelRuleAction::Blackhole, None));
            }
            (RuleAction::Unreachable, _) => {
                out.insert(one(pref, KernelRuleAction::Unreachable, None));
            }
        }
    }
}

/// The routing marks the router sets, by name, each with its table when one
/// has that name (the mark sends packets there, as in RouterOS v7): the
/// mangle's `mark-routing`, and the encrypted packets of a WireGuard
/// interface with a `vrf` (G1.31c: the kernel marks them with the VRF's
/// routing mark, `wg->fwmark`, and routes them by it, `socket.c`).
pub fn routing_marks(cfg: &Config) -> BTreeMap<Name, Option<RoutingTable>> {
    let mangle = cfg
        .ip
        .firewall
        .mangle
        .iter()
        .filter(|r| !r.disabled)
        .filter_map(|r| match &r.action {
            Action::MarkRouting {
                new_routing_mark, ..
            } => Some(new_routing_mark.clone()),
            _ => None,
        });
    let sockets = wireguard_vrfs(cfg).filter_map(|(_, vrf)| vrf.as_str().parse::<Name>().ok());
    mangle
        .chain(sockets)
        .map(|name| {
            let table = name.as_str().parse::<RoutingTable>().ok();
            let table = table.filter(|t| route::table_id(cfg, t).is_some());
            (name, table)
        })
        .collect()
}

/// The routing marks of the mangle's `mark-routing` rules, by name.
fn mangle_marks(cfg: &Config) -> BTreeSet<&Name> {
    cfg.ip
        .firewall
        .mangle
        .iter()
        .filter(|r| !r.disabled)
        .filter_map(|r| match &r.action {
            Action::MarkRouting {
                new_routing_mark, ..
            } => Some(new_routing_mark),
            _ => None,
        })
        .collect()
}

/// The enabled WireGuard interfaces whose encrypted packets go by a VRF
/// (`vrf`, RouterOS 7.21), with it.
pub fn wireguard_vrfs(cfg: &Config) -> impl Iterator<Item = (&IfName, &IfName)> {
    cfg.interfaces
        .values()
        .filter(|i| !i.disabled)
        .filter_map(|i| match &i.kind {
            InterfaceKind::Wireguard(w) => w.vrf.as_ref().map(|v| (&i.name, v)),
            _ => None,
        })
}

/// The packet mark WireGuard interface `w`'s encrypted packets carry
/// (`WGDEVICE_A_FWMARK`): its VRF's routing mark, 0 without one.
pub fn wireguard_fwmark(w: &corerouter_model::wireguard::Wireguard) -> u32 {
    w.vrf
        .as_ref()
        .and_then(|v| v.as_str().parse::<Name>().ok())
        .map_or(0, |n| mark_value(MarkKind::Routing, &n))
}

/// The rule list `cfg` asks of the kernel (without the kernel's own).
pub fn expected_rules(cfg: &Config) -> BTreeSet<KernelRule> {
    let mut out = BTreeSet::new();
    let marks = routing_marks(cfg);
    let mangle = mangle_marks(cfg);
    let with_table = marks.iter().filter_map(|(n, t)| Some((n, t.as_ref()?)));
    for (pref, (name, table)) in (FIRST_MARK_PREF..=LAST_MARK_PREF).zip(with_table) {
        let Some(table) = route::table_id(cfg, table) else {
            continue;
        };
        // G1.31c: a mark only WireGuard sets is for the router's own
        // packets (`iif lo`): a received packet that kept it (a veth in the
        // same namespace does not clear `skb->mark`) must still go by its
        // own VRF (`l3mdev`, after this rule), never back out.
        let iif = if mangle.contains(name) {
            None
        } else {
            "lo".parse::<IfName>().ok()
        };
        for v6 in [false, true] {
            out.insert(KernelRule {
                pref,
                v6,
                src: None,
                dst: None,
                iif: iif.clone(),
                mark: Some(mark_value(MarkKind::Routing, name)),
                action: KernelRuleAction::Table(table),
                suppress: None,
                l3mdev: false,
            });
        }
    }
    let has_vrf = cfg
        .interfaces
        .values()
        .any(|i| matches!(i.kind, InterfaceKind::Vrf { .. }));
    if has_vrf {
        for v6 in [false, true] {
            out.insert(KernelRule {
                pref: VRF_UNREACH_PREF,
                v6,
                src: None,
                dst: None,
                iif: None,
                mark: None,
                action: KernelRuleAction::Unreachable,
                suppress: None,
                l3mdev: true,
            });
        }
    }
    for (pos, r) in cfg.routing.rules.iter().enumerate() {
        kernel_rules_of(cfg, r, pos, &mut out);
    }
    out
}

/// A packet to look up.
#[derive(Debug, Clone, Copy)]
pub struct RulePacket<'a> {
    pub src: Option<IpAddr>,
    pub dst: IpAddr,
    /// Incoming interface; `None`: this router's own packet (`iif lo`).
    pub iif: Option<&'a IfName>,
    pub mark: u32,
    /// Kernel table of the VRF it is in (the `l3mdev` rule's match).
    pub vrf: Option<u32>,
}

/// One rule the packet matched, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RuleStep {
    pub pref: u32,
    pub action: KernelRuleAction,
    /// It decided: a route in the table, or a discard.
    pub decided: bool,
}

/// How a walk ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleVerdict {
    Table(u32),
    Blackhole,
    Unreachable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleWalk {
    pub verdict: RuleVerdict,
    pub steps: Vec<RuleStep>,
}

fn matches(r: &KernelRule, p: &RulePacket<'_>) -> bool {
    let net = |n: Option<IpNet>, ip: Option<IpAddr>| match (n, ip) {
        (None, _) => true,
        (Some(n), Some(ip)) => n.contains(&ip),
        // The kernel compares 0.0.0.0 here (`saddr` not chosen yet): a prefix
        // of length > 0 that holds it is not a real source.
        (Some(_), None) => false,
    };
    r.v6 == p.dst.is_ipv6()
        && net(r.src, p.src)
        && net(r.dst, Some(p.dst))
        && r.iif.as_ref().is_none_or(|i| match p.iif {
            Some(have) => i == have,
            // `ip_route_output_key_hash` sets `flowi4_iif = LOOPBACK_IFINDEX`.
            None => i.as_str() == "lo",
        })
        && r.mark.is_none_or(|m| (p.mark ^ m) & ROUTING_MARK_MASK == 0)
        && (!r.l3mdev || p.vrf.is_some())
}

/// Walk `rules` (sorted by priority, as [`expected_rules`] gives) as the
/// kernel would, after its rule 0 (`local`, which the caller answers).
/// `has_route(table, suppress)`: the table holds a route for the packet,
/// not hidden by `suppress_prefixlength`.
pub fn walk<'r>(
    rules: impl IntoIterator<Item = &'r KernelRule>,
    p: &RulePacket<'_>,
    mut has_route: impl FnMut(u32, Option<u8>) -> bool,
) -> RuleWalk {
    let mut steps = Vec::new();
    let mut vrf_done = false;
    let mut vrf_hit = |steps: &mut Vec<RuleStep>, has: &mut dyn FnMut(u32, Option<u8>) -> bool| {
        let t = p.vrf.filter(|_| !vrf_done)?;
        vrf_done = true;
        let decided = has(t, None);
        steps.push(RuleStep {
            pref: L3MDEV_PREF,
            action: KernelRuleAction::Table(t),
            decided,
        });
        decided.then_some(t)
    };
    for r in rules {
        if r.pref > L3MDEV_PREF
            && let Some(t) = vrf_hit(&mut steps, &mut has_route)
        {
            return RuleWalk {
                verdict: RuleVerdict::Table(t),
                steps,
            };
        }
        if !matches(r, p) {
            continue;
        }
        let (decided, verdict) = match r.action {
            KernelRuleAction::Table(t) => (has_route(t, r.suppress), RuleVerdict::Table(t)),
            KernelRuleAction::Blackhole => (true, RuleVerdict::Blackhole),
            KernelRuleAction::Unreachable => (true, RuleVerdict::Unreachable),
            // Never in `expected_rules`; a walk does not decide on it.
            KernelRuleAction::Other(_) => (false, RuleVerdict::Unreachable),
        };
        steps.push(RuleStep {
            pref: r.pref,
            action: r.action,
            decided,
        });
        if decided {
            return RuleWalk { verdict, steps };
        }
    }
    if let Some(t) = vrf_hit(&mut steps, &mut has_route) {
        return RuleWalk {
            verdict: RuleVerdict::Table(t),
            steps,
        };
    }
    let decided = has_route(MAIN_TABLE_ID, None);
    steps.push(RuleStep {
        pref: MAIN_PREF,
        action: KernelRuleAction::Table(MAIN_TABLE_ID),
        decided,
    });
    RuleWalk {
        verdict: if decided {
            RuleVerdict::Table(MAIN_TABLE_ID)
        } else {
            RuleVerdict::Unreachable
        },
        steps,
    }
}

/// The lab's whole list: `rules` and what a kernel starts with.
pub fn listed(rules: &BTreeSet<KernelRule>) -> Vec<KernelRuleRow> {
    let builtin = |pref, v6, table| KernelRuleRow {
        rule: KernelRule {
            pref,
            v6,
            src: None,
            dst: None,
            iif: None,
            mark: None,
            action: KernelRuleAction::Table(table),
            suppress: None,
            l3mdev: false,
        },
        owner: RuleOwner::Kernel,
        protocol: 2,
    };
    let mut out: Vec<KernelRuleRow> = rules
        .iter()
        .map(|r| KernelRuleRow {
            rule: r.clone(),
            owner: RuleOwner::Corerouter,
            protocol: RULE_PROTOCOL,
        })
        .collect();
    for v6 in [false, true] {
        out.push(builtin(0, v6, 255));
        out.push(builtin(MAIN_PREF, v6, MAIN_TABLE_ID));
        if !v6 {
            out.push(builtin(DEFAULT_PREF, v6, 253));
        }
    }
    out.sort_by(|a, b| a.rule.cmp(&b.rule));
    out
}

#[cfg(test)]
mod tests {
    use corerouter_model::firewall::FirewallRule;
    use corerouter_model::routing_table::NamedTable;
    use corerouter_model::{Interface, ItemId};

    use super::*;

    fn n(s: &str) -> IfName {
        s.parse().unwrap()
    }

    fn rule(action: RuleAction, table: &str) -> RoutingRule {
        RoutingRule {
            id: ItemId(1),
            src_address: None,
            dst_address: None,
            interface: None,
            routing_mark: None,
            action,
            table: table.parse().unwrap(),
            min_prefix: None,
            disabled: false,
            comment: String::new(),
        }
    }

    fn cfg() -> Config {
        let mut c = Config::default();
        c.routing.tables.insert(
            n("isp2"),
            NamedTable {
                name: n("isp2"),
                table: 1000,
                comment: String::new(),
            },
        );
        c
    }

    #[test]
    fn each_action_gives_its_kernel_rules() {
        let mut c = cfg();
        let mut a = rule(RuleAction::LookupOnlyInTable, "isp2");
        a.src_address = Some("10.0.0.0/24".parse().unwrap());
        let mut b = rule(RuleAction::Drop, "main");
        b.dst_address = Some("2001:db8::/32".parse().unwrap());
        c.routing.rules = vec![a, b, rule(RuleAction::Lookup, "isp2")];
        let got: Vec<String> = expected_rules(&c).iter().map(ToString::to_string).collect();
        assert_eq!(
            got,
            [
                "rule 2000 from 10.0.0.0/24 lookup 1000",
                "rule 2001 from 10.0.0.0/24 unreachable",
                "rule 2002 ipv6 to 2001:db8::/32 blackhole",
                "rule 2004 lookup 1000",
                "rule 2004 ipv6 lookup 1000",
            ]
        );
    }

    #[test]
    fn a_disabled_rule_keeps_its_place() {
        let mut c = cfg();
        let mut off = rule(RuleAction::Lookup, "isp2");
        off.disabled = true;
        c.routing.rules = vec![off, rule(RuleAction::Unreachable, "main")];
        let got: Vec<u32> = expected_rules(&c).iter().map(|r| r.pref).collect();
        assert_eq!(got, [2002, 2002]);
    }

    #[test]
    fn prefix_zero_is_no_selector_but_keeps_the_family() {
        let mut c = cfg();
        let mut r = rule(RuleAction::Drop, "main");
        r.dst_address = Some("0.0.0.0/0".parse().unwrap());
        c.routing.rules = vec![r];
        let got: Vec<KernelRule> = expected_rules(&c).into_iter().collect();
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].v6, got[0].dst), (false, None));
    }

    #[test]
    fn a_mark_that_names_a_table_gets_a_rule_before_the_vrf() {
        let mut c = cfg();
        c.interfaces.insert(
            n("blue"),
            Interface::new(n("blue"), InterfaceKind::Vrf { table: 1001 }),
        );
        let rule = |mark: &str| {
            serde_json::from_value::<FirewallRule>(serde_json::json!({
                "id": "*1", "chain": "prerouting",
                "action": {"type": "mark-routing", "new_routing_mark": mark}
            }))
            .unwrap()
        };
        c.ip.firewall.mangle.push(rule("isp2"));
        c.ip.firewall.mangle.push(rule("nothing"));
        let got: Vec<KernelRule> = expected_rules(&c).into_iter().collect();
        let prefs: Vec<(u32, bool)> = got.iter().map(|r| (r.pref, r.l3mdev)).collect();
        assert_eq!(
            prefs,
            [(100, false), (100, false), (1001, true), (1001, true)],
            "{got:?}"
        );
        assert_eq!(got[0].action, KernelRuleAction::Table(1000));
        assert_eq!(
            routing_marks(&c).values().filter(|t| t.is_none()).count(),
            1,
            "a mark without table is kept apart"
        );
    }

    fn packet<'a>(dst: &str) -> RulePacket<'a> {
        RulePacket {
            src: None,
            dst: dst.parse().unwrap(),
            iif: None,
            mark: 0,
            vrf: None,
        }
    }

    #[test]
    fn lookup_falls_through_and_only_in_table_does_not() {
        let mut c = cfg();
        c.routing.rules = vec![rule(RuleAction::Lookup, "isp2")];
        let w = walk(&expected_rules(&c), &packet("8.8.8.8"), |t, _| t == 254);
        assert_eq!(w.verdict, RuleVerdict::Table(254));
        assert_eq!(w.steps.len(), 2);
        assert!(!w.steps[0].decided);
        c.routing.rules = vec![rule(RuleAction::LookupOnlyInTable, "isp2")];
        let w = walk(&expected_rules(&c), &packet("8.8.8.8"), |t, _| t == 254);
        assert_eq!(w.verdict, RuleVerdict::Unreachable);
        assert_eq!(w.steps.last().map(|s| s.pref), Some(2001));
        let w = walk(&expected_rules(&c), &packet("8.8.8.8"), |t, _| t == 1000);
        assert_eq!(w.verdict, RuleVerdict::Table(1000));
    }

    #[test]
    fn selectors_match_like_the_kernel() {
        let mut c = cfg();
        let mut r = rule(RuleAction::Drop, "main");
        r.src_address = Some("10.0.0.0/24".parse().unwrap());
        r.interface = Some(n("ether1"));
        c.routing.rules = vec![r];
        let want = expected_rules(&c);
        let has = |t: u32, _: Option<u8>| t == 254;
        assert_eq!(
            walk(&want, &packet("8.8.8.8"), has).verdict,
            RuleVerdict::Table(254)
        );
        let iif = n("ether1");
        let mut p = packet("8.8.8.8");
        p.src = Some("10.0.0.9".parse().unwrap());
        assert_eq!(
            walk(&want, &p, has).verdict,
            RuleVerdict::Table(254),
            "no iif"
        );
        p.iif = Some(&iif);
        assert_eq!(walk(&want, &p, has).verdict, RuleVerdict::Blackhole);
        assert_eq!(
            walk(&want, &packet("2001:db8::1"), has).verdict,
            RuleVerdict::Table(254),
            "the rule is IPv4"
        );
    }

    #[test]
    fn the_mark_is_compared_under_its_mask() {
        let mut c = cfg();
        let name: Name = "isp2".parse().unwrap();
        let v = mark_value(MarkKind::Routing, &name);
        let mut r = rule(RuleAction::Lookup, "isp2");
        r.routing_mark = Some(name);
        c.routing.rules = vec![r];
        let want = expected_rules(&c);
        let mut p = packet("8.8.8.8");
        let has = |t: u32, _: Option<u8>| t == 254 || t == 1000;
        assert_eq!(walk(&want, &p, has).verdict, RuleVerdict::Table(254));
        p.mark = v | 0x1234; // the packet mark in the low bits does not matter
        assert_eq!(walk(&want, &p, has).verdict, RuleVerdict::Table(1000));
    }

    #[test]
    fn a_vrf_packet_stops_at_its_table() {
        let mut c = cfg();
        c.interfaces.insert(
            n("blue"),
            Interface::new(n("blue"), InterfaceKind::Vrf { table: 1001 }),
        );
        c.routing.rules = vec![rule(RuleAction::Lookup, "isp2")];
        let mut p = packet("8.8.8.8");
        p.vrf = Some(1001);
        let want = expected_rules(&c);
        let w = walk(&want, &p, |t, _| t != 1001);
        assert_eq!(
            w.verdict,
            RuleVerdict::Unreachable,
            "no leak to main: {w:?}"
        );
        let w = walk(&want, &p, |t, _| t == 1001);
        assert_eq!(w.verdict, RuleVerdict::Table(1001));
    }

    #[test]
    fn priorities_read_back() {
        for pos in [0, 1, 4095] {
            assert_eq!(pos_of_pref(rule_pref(pos)), Some(pos));
            assert_eq!(pos_of_pref(rule_pref(pos) + 1), Some(pos));
        }
        assert_eq!(pos_of_pref(1999), None);
        assert_eq!(pos_of_pref(MAIN_PREF), None);
        assert!(rule_pref(4095) < MAIN_PREF);
    }
}

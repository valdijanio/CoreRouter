//! G1.27e: the kernel's rule list over netlink (`RTM_{GET,NEW,DEL}RULE`,
//! `FRA_*`). Pure policy is `corerouter_hal::policy`; here it is read and
//! written.
//!
//! [`sync`] compares with what the kernel holds rather than with the last
//! config, so a daemon restarting over a running kernel neither duplicates a
//! rule (without `NLM_F_EXCL` the kernel takes twins) nor leaves a stale one.
//! Only rules of [`RULE_PROTOCOL`] are ours: another program's are read and
//! never touched, in any order they sit (`fib_newrule` keeps the list sorted
//! by priority, and equal priorities in order of arrival).
//!
//! Adds go in falling priority and removals in rising priority: `fib_newrule`
//! and `rule_find` walk the list from the top until they pass the spot, so
//! each stays at the head of the walk (`net/core/fib_rules.c`). New ones go
//! in before old ones leave, so no packet sees neither.
//!
//! The `l3mdev unreachable` rule is added with the first VRF and stays, like
//! the kernel's own `l3mdev` rule: it matches nothing without a VRF, and
//! leaves the list as it found it for whoever shares the namespace.

use std::collections::BTreeSet;
use std::net::IpAddr;

use corerouter_hal::HalError;
use corerouter_hal::policy::{
    KernelRule, KernelRuleAction, KernelRuleRow, ROUTING_MARK_MASK, RULE_PROTOCOL, RuleOwner,
};
use futures_util::stream::TryStreamExt;
use ipnet::IpNet;
use rtnetlink::packet_route::route::RouteProtocol;
use rtnetlink::packet_route::rule::{RuleAction, RuleAttribute, RuleMessage};
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::IpVersion;

use crate::netlink::{Kernel, errno, readable, with_kernel};

const ESRCH: i32 = 3;
const ENOENT: i32 = 2;
const EEXIST: i32 = 17;
/// `RTPROT_KERNEL`.
const KERNEL_PROTOCOL: u8 = 2;
/// Bound on a dump (hostile input: the kernel's list has no limit).
const MAX_DUMP: usize = 1 << 20;

fn message(r: &KernelRule) -> RuleMessage {
    let mut m = RuleMessage::default();
    m.header.family = if r.v6 {
        AddressFamily::Inet6
    } else {
        AddressFamily::Inet
    };
    let a = &mut m.attributes;
    a.push(RuleAttribute::Priority(r.pref));
    a.push(RuleAttribute::Protocol(RouteProtocol::from(RULE_PROTOCOL)));
    if let Some(s) = r.src {
        m.header.src_len = s.prefix_len();
        a.push(RuleAttribute::Source(s.addr()));
    }
    if let Some(d) = r.dst {
        m.header.dst_len = d.prefix_len();
        a.push(RuleAttribute::Destination(d.addr()));
    }
    if let Some(i) = &r.iif {
        a.push(RuleAttribute::Iifname(i.as_str().to_owned()));
    }
    if let Some(v) = r.mark {
        a.push(RuleAttribute::FwMark(v));
        a.push(RuleAttribute::FwMask(ROUTING_MARK_MASK));
    }
    if r.l3mdev {
        a.push(RuleAttribute::L3MDev(true));
    }
    if let Some(s) = r.suppress {
        a.push(RuleAttribute::SuppressPrefixLen(u32::from(s)));
    }
    m.header.action = match r.action {
        KernelRuleAction::Table(t) => {
            a.push(RuleAttribute::Table(t));
            RuleAction::ToTable
        }
        KernelRuleAction::Blackhole => RuleAction::Blackhole,
        KernelRuleAction::Unreachable => RuleAction::Unreachable,
        // Never in `expected_rules`; a dumped rule is not written back.
        KernelRuleAction::Other(code) => RuleAction::Other(code),
    };
    m
}

/// A dumped rule. `None` for what this model cannot hold (a name that is not
/// an interface name): it is someone else's and stays out of the comparison.
fn parse(m: &RuleMessage) -> Option<KernelRuleRow> {
    let h = &m.header;
    let v6 = h.family == AddressFamily::Inet6;
    let mut r = KernelRule {
        pref: 0,
        v6,
        src: None,
        dst: None,
        iif: None,
        mark: None,
        action: KernelRuleAction::Unreachable,
        suppress: None,
        l3mdev: false,
    };
    let mut table = u32::from(h.table);
    let mut protocol = 0u8;
    let prefix = |ip: &IpAddr, len: u8| IpNet::new(*ip, len).ok();
    for a in &m.attributes {
        match a {
            RuleAttribute::Priority(p) => r.pref = *p,
            RuleAttribute::Source(ip) => r.src = prefix(ip, h.src_len),
            RuleAttribute::Destination(ip) => r.dst = prefix(ip, h.dst_len),
            RuleAttribute::Iifname(n) => r.iif = Some(n.parse().ok()?),
            RuleAttribute::FwMark(v) => r.mark = Some(*v),
            RuleAttribute::Table(t) => table = *t,
            // The kernel always reports it, -1 for none (`fib_nl_fill_rule`).
            RuleAttribute::SuppressPrefixLen(s) => r.suppress = u8::try_from(*s).ok(),
            RuleAttribute::L3MDev(on) => r.l3mdev = *on,
            RuleAttribute::Protocol(p) => protocol = u8::from(*p),
            _ => {}
        }
    }
    r.action = match h.action {
        RuleAction::ToTable => KernelRuleAction::Table(table),
        RuleAction::Blackhole => KernelRuleAction::Blackhole,
        RuleAction::Unreachable => KernelRuleAction::Unreachable,
        other => KernelRuleAction::Other(u8::from(other)),
    };
    let owner = match protocol {
        RULE_PROTOCOL => RuleOwner::Corerouter,
        KERNEL_PROTOCOL => RuleOwner::Kernel,
        _ => RuleOwner::Foreign,
    };
    Some(KernelRuleRow {
        rule: r,
        owner,
        protocol,
    })
}

impl Kernel {
    async fn rule_rows(&self) -> Result<Vec<KernelRuleRow>, String> {
        let mut out = Vec::new();
        for v in [IpVersion::V4, IpVersion::V6] {
            let mut s = self.handle.rule().get(v).execute();
            while let Some(m) = s
                .try_next()
                .await
                .map_err(|e| format!("listing rules: {}", readable(&e)))?
            {
                if out.len() >= MAX_DUMP {
                    return Err(format!("more than {MAX_DUMP} rules"));
                }
                out.extend(parse(&m));
            }
        }
        out.sort_by(|a, b| a.rule.cmp(&b.rule));
        Ok(out)
    }

    async fn rule_add(&self, r: &KernelRule) -> Result<(), String> {
        let mut req = self.handle.rule().add();
        *req.message_mut() = message(r);
        match req.execute().await {
            Ok(()) => Ok(()),
            // A twin of ours: nothing to do.
            Err(e) if errno(&e) == Some(EEXIST) => Ok(()),
            Err(e) => Err(format!("add {r}: {}", readable(&e))),
        }
    }

    async fn rule_del(&self, r: &KernelRule) -> Result<(), String> {
        match self.handle.rule().del(message(r)).execute().await {
            Ok(()) => Ok(()),
            Err(e) if matches!(errno(&e), Some(ESRCH | ENOENT)) => Ok(()),
            Err(e) => Err(format!("remove {r}: {}", readable(&e))),
        }
    }

    async fn rules_to(&self, want: &BTreeSet<KernelRule>) -> Result<(), String> {
        let have: BTreeSet<KernelRule> = self
            .rule_rows()
            .await?
            .into_iter()
            .filter(|r| r.owner == RuleOwner::Corerouter)
            .map(|r| r.rule)
            .collect();
        let mut done: Vec<&KernelRule> = Vec::new();
        let fresh: Vec<&KernelRule> = want.difference(&have).collect();
        for r in fresh.into_iter().rev() {
            if let Err(e) = self.rule_add(r).await {
                for back in done {
                    if let Err(b) = self.rule_del(back).await {
                        log::error!("restoring the rule list: {b}");
                    }
                }
                return Err(e);
            }
            done.push(r);
        }
        let mut gone: Vec<&KernelRule> = Vec::new();
        for r in have.difference(want).filter(|r| !r.l3mdev) {
            if let Err(e) = self.rule_del(r).await {
                for back in gone.into_iter().rev() {
                    if let Err(b) = self.rule_add(back).await {
                        log::error!("restoring the rule list: {b}");
                    }
                }
                for back in done {
                    if let Err(b) = self.rule_del(back).await {
                        log::error!("restoring the rule list: {b}");
                    }
                }
                return Err(e);
            }
            gone.push(r);
        }
        Ok(())
    }
}

/// The kernel's whole rule list, in its order.
pub(crate) fn dump() -> Result<Vec<KernelRuleRow>, HalError> {
    with_kernel(|k| async move { k.rule_rows().await.map_err(HalError::Io) })
}

/// Make CoreRouter's rules exactly `want`, all or nothing.
pub(crate) fn sync(want: &BTreeSet<KernelRule>) -> Result<(), HalError> {
    with_kernel(|k| async move { k.rules_to(want).await.map_err(HalError::Rejected) })
}

#[cfg(test)]
mod tests {
    use corerouter_hal::policy::FIRST_RULE_PREF;

    use super::*;

    #[test]
    fn a_rule_reads_back_from_its_message() {
        let r = KernelRule {
            pref: FIRST_RULE_PREF,
            v6: false,
            src: Some("10.0.0.0/24".parse().unwrap()),
            dst: Some("192.0.2.0/25".parse().unwrap()),
            iif: Some("ether1".parse().unwrap()),
            mark: Some(0x1234_0000),
            action: KernelRuleAction::Table(1000),
            suppress: Some(0),
            l3mdev: false,
        };
        let row = parse(&message(&r)).unwrap();
        assert_eq!(row.rule, r);
        assert_eq!((row.owner, row.protocol), (RuleOwner::Corerouter, RULE_PROTOCOL));
    }

    #[test]
    fn the_kernels_no_suppress_is_none() {
        let mut m = message(&KernelRule {
            pref: 7,
            v6: true,
            src: None,
            dst: None,
            iif: None,
            mark: None,
            action: KernelRuleAction::Blackhole,
            suppress: None,
            l3mdev: false,
        });
        m.attributes.push(RuleAttribute::SuppressPrefixLen(u32::MAX));
        assert_eq!(parse(&m).unwrap().rule.suppress, None);
    }
}

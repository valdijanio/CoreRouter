//! Pure diff `from` → `to` into an ordered list of kernel operations.
//!
//! No kernel, no I/O: the plan is computed and unit-tested on any platform.
//! The netlink executor (`netlink.rs`) runs it in order and, if one step
//! fails, undoes the steps already done in reverse.
//!
//! Order (teardown first, then build):
//! 0. remove static routes that go away (or whose link is rebuilt, below);
//! 1. remove addresses that go away, or whose link is disabled, recreated or
//!    changes master (Linux drops IPv6 addresses of a link that goes down or
//!    joins a VRF);
//! 2. detach bridge ports / bond slaves / VRF members that leave (or change)
//!    their master;
//! 3. delete virtual links, VLAN children before their parents;
//! 4. create virtual links, parents before VLAN children, then change in
//!    place the bond settings the kernel takes on a live bond;
//! 5. MTU: decreases children-first, then increases parents-first, so a VLAN
//!    never exceeds its parent on the way (nor on the way back, in rollback);
//! 6. attach bridge ports / bond slaves / VRF members;
//! 7. add addresses;
//! 8. admin state up/down, parents first (also of links whose master changed:
//!    a bond brings a slave up when it takes it, and leaves it down after);
//! 9. add static routes that arrive (or whose link was rebuilt).
//!
//! The kernel deletes routes by itself when their link goes down, is
//! recreated, is enslaved to (or released from) a VRF, or loses its last
//! IPv4 address. Those links are "rebuilt": their routes are removed
//! explicitly in step 0 and added again in step 9, so the undo of a failed
//! apply can put every route back, and the kernel never holds a route the
//! running config does not know about. Which routes belong in the kernel is
//! decided by `corerouter_model::route::reach` — the same function behind
//! the A flag of `ip.route.list`.
//!
//! Only interfaces present in `from` or `to` ever appear in the plan, so a
//! host interface outside the config is never touched. Physical ports
//! (`Ethernet`) are configured but never created or deleted.

use std::collections::BTreeSet;
use std::fmt;

use corerouter_hal::HalError;
use corerouter_hal::drift::{self, Snapshot, active_addresses, master};
pub use corerouter_hal::drift::{KernelRoute, kernel_routes};
use corerouter_model::{BondMode, Config, HashPolicy, IfName, InterfaceKind, LacpRate};
use ipnet::IpNet;

/// A link CoreRouter creates and deletes itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkSpec {
    /// 802.1Q VLAN on top of `parent`.
    Vlan {
        parent: IfName,
        vlan_id: u16,
    },
    Bridge,
    /// Linux `dummy`: what a RouterOS-style loopback is in the kernel.
    Dummy,
    /// Linux `vrf` (l3mdev) bound to kernel routing table `table`.
    Vrf {
        table: u32,
    },
    /// Linux `bond`. What [`bond_in_place`] accepts changes on the live bond
    /// (same ifindex, slaves stay); a new mode or LACP rate recreates it,
    /// with its slaves released first and taken back after.
    Bond {
        mode: BondMode,
        primary: Option<IfName>,
        hash: HashPolicy,
        lacp_rate: LacpRate,
        mii_interval_ms: u32,
        min_links: u32,
    },
}

impl LinkSpec {
    /// `None` for physical ports, which already exist and are never created.
    pub fn of(kind: &InterfaceKind) -> Option<Self> {
        match kind {
            InterfaceKind::Ethernet => None,
            InterfaceKind::Vlan { parent, vlan_id } => Some(Self::Vlan {
                parent: parent.clone(),
                vlan_id: vlan_id.get(),
            }),
            InterfaceKind::Bridge => Some(Self::Bridge),
            InterfaceKind::Loopback => Some(Self::Dummy),
            InterfaceKind::Vrf { table } => Some(Self::Vrf { table: *table }),
            InterfaceKind::Bonding {
                mode,
                primary,
                transmit_hash_policy,
                lacp_rate,
                mii_interval_ms,
                min_links,
            } => Some(Self::Bond {
                mode: *mode,
                primary: primary.clone(),
                hash: *transmit_hash_policy,
                lacp_rate: *lacp_rate,
                mii_interval_ms: *mii_interval_ms,
                min_links: *min_links,
            }),
        }
    }

    /// Kernel `IFLA_INFO_KIND`.
    pub fn kernel_kind(&self) -> &'static str {
        match self {
            Self::Vlan { .. } => "vlan",
            Self::Bridge => "bridge",
            Self::Dummy => "dummy",
            Self::Vrf { .. } => "vrf",
            Self::Bond { .. } => "bond",
        }
    }
}

impl fmt::Display for LinkSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vlan { parent, vlan_id } => write!(f, "vlan {vlan_id} on '{parent}'"),
            Self::Bridge => f.write_str("bridge"),
            Self::Dummy => f.write_str("loopback (dummy)"),
            Self::Vrf { table } => write!(f, "vrf (table {table})"),
            Self::Bond { mode, .. } => write!(f, "bonding ({mode})"),
        }
    }
}

/// One bond setting changed on a live bond (`IFLA_BOND_*` in an
/// `RTM_NEWLINK` on its ifindex, the kernel's `bond_changelink`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BondSetting {
    MiiInterval(u32),
    MinLinks(u32),
    Hash(HashPolicy),
    /// `None` clears it (ifindex 0).
    Primary(Option<IfName>),
}

impl fmt::Display for BondSetting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MiiInterval(ms) => write!(f, "mii-interval {ms}ms"),
            Self::MinLinks(n) => write!(f, "min-links {n}"),
            Self::Hash(h) => write!(f, "transmit-hash-policy {}", h.label()),
            Self::Primary(Some(p)) => write!(f, "primary {p}"),
            Self::Primary(None) => f.write_str("primary none"),
        }
    }
}

/// The settings that take bond `from` to `to` without recreating it, or
/// `None` when the kernel only takes the change on a new bond. Only what
/// the kernel uses in the mode is compared, as when the bond is created.
///
/// Linux `drivers/net/bonding/bond_options.c` flags each option: `mode` is
/// `BOND_OPTFLAG_NOSLAVES | BOND_OPTFLAG_IFDOWN` ("unable to set option
/// because the bond device has slaves") and `lacp_rate` is
/// `BOND_OPTFLAG_IFDOWN` ("…because the bond is up"); `miimon`,
/// `min_links`, `xmit_hash_policy` and `primary` have no flag, so they
/// change on a bond that is up and has slaves (checked on Linux 7.0).
pub fn bond_in_place(from: &LinkSpec, to: &LinkSpec) -> Option<Vec<BondSetting>> {
    let (
        LinkSpec::Bond {
            mode,
            primary,
            hash,
            lacp_rate,
            mii_interval_ms,
            min_links,
        },
        LinkSpec::Bond {
            mode: mode2,
            primary: primary2,
            hash: hash2,
            lacp_rate: lacp_rate2,
            mii_interval_ms: mii2,
            min_links: min_links2,
        },
    ) = (from, to)
    else {
        return None;
    };
    if mode != mode2 || (*mode == BondMode::Lacp && lacp_rate != lacp_rate2) {
        return None;
    }
    let mut out = Vec::new();
    if mii_interval_ms != mii2 {
        out.push(BondSetting::MiiInterval(*mii2));
    }
    if min_links != min_links2 {
        out.push(BondSetting::MinLinks(*min_links2));
    }
    if mode.hashes() && hash != hash2 {
        out.push(BondSetting::Hash(*hash2));
    }
    if mode.has_primary() && primary != primary2 {
        out.push(BondSetting::Primary(primary2.clone()));
    }
    Some(out)
}

/// One kernel operation. Each one is small enough to undo on its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    DelRoute(KernelRoute),
    DelAddress {
        link: IfName,
        addr: IpNet,
    },
    SetMaster {
        link: IfName,
        master: Option<IfName>,
    },
    DeleteLink {
        link: IfName,
        spec: LinkSpec,
    },
    CreateLink {
        link: IfName,
        spec: LinkSpec,
    },
    /// Bond settings changed in place: what [`bond_in_place`] gives for
    /// `from` → `to`. Undone by the same op with the two swapped.
    SetBond {
        link: IfName,
        from: LinkSpec,
        to: LinkSpec,
    },
    /// `u32` like the kernel: `lo` has MTU 65536, and undo must restore it.
    SetMtu {
        link: IfName,
        mtu: u32,
    },
    AddAddress {
        link: IfName,
        addr: IpNet,
    },
    SetUp {
        link: IfName,
        up: bool,
    },
    AddRoute(KernelRoute),
}

impl Op {
    pub fn link(&self) -> &IfName {
        match self {
            Self::DelAddress { link, .. }
            | Self::SetMaster { link, .. }
            | Self::DeleteLink { link, .. }
            | Self::CreateLink { link, .. }
            | Self::SetBond { link, .. }
            | Self::SetMtu { link, .. }
            | Self::AddAddress { link, .. }
            | Self::SetUp { link, .. } => link,
            Self::DelRoute(r) | Self::AddRoute(r) => &r.link,
        }
    }
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DelAddress { link, addr } => write!(f, "remove address {addr} from '{link}'"),
            Self::SetMaster { link, master: None } => {
                write!(f, "detach '{link}' from its bridge/bond/VRF")
            }
            Self::SetMaster {
                link,
                master: Some(m),
            } => write!(f, "attach '{link}' to '{m}'"),
            Self::DeleteLink { link, spec } => write!(f, "delete {spec} '{link}'"),
            Self::CreateLink { link, spec } => write!(f, "create {spec} '{link}'"),
            Self::SetBond { link, from, to } => {
                write!(f, "set")?;
                for (i, s) in bond_in_place(from, to)
                    .unwrap_or_default()
                    .iter()
                    .enumerate()
                {
                    write!(f, "{}{s}", if i == 0 { " " } else { ", " })?;
                }
                write!(f, " on bonding '{link}'")
            }
            Self::SetMtu { link, mtu } => write!(f, "set MTU of '{link}' to {mtu}"),
            Self::AddAddress { link, addr } => write!(f, "add address {addr} to '{link}'"),
            Self::SetUp { link, up: true } => write!(f, "bring '{link}' up"),
            Self::SetUp { link, up: false } => write!(f, "bring '{link}' down"),
            Self::AddRoute(r) => write!(f, "add {r}"),
            Self::DelRoute(r) => write!(f, "remove {r}"),
        }
    }
}

/// Number of VLAN hops under `name` (0 for anything that is not a VLAN).
/// Bounded by the interface count, so a cyclic config cannot loop forever.
fn depth(cfg: &Config, name: &IfName) -> usize {
    let mut d = 0;
    let mut cur = name;
    while let Some(InterfaceKind::Vlan { parent, .. }) = cfg.interfaces.get(cur).map(|i| &i.kind) {
        d += 1;
        if d > cfg.interfaces.len() {
            break;
        }
        cur = parent;
    }
    d
}

/// Virtual links of `from` that must be deleted: gone from `to`, changed
/// spec, or stacked (VLAN) on a link that is itself deleted, since the
/// kernel removes VLANs together with their parent.
fn doomed(from: &Config, to: &Config) -> Result<BTreeSet<IfName>, HalError> {
    let mut out = BTreeSet::new();
    for (name, old) in &from.interfaces {
        let old_spec = LinkSpec::of(&old.kind);
        let new_spec = to.interfaces.get(name).map(|i| LinkSpec::of(&i.kind));
        match (&old_spec, &new_spec) {
            (None, Some(Some(s))) => {
                return Err(HalError::Rejected(format!(
                    "'{name}' is a physical port and cannot become a {s}"
                )));
            }
            (Some(s), Some(None)) => {
                return Err(HalError::Rejected(format!(
                    "'{name}' is a {s} and cannot become a physical port"
                )));
            }
            (Some(_), None) => {
                out.insert(name.clone());
            }
            (Some(a), Some(Some(b))) if a != b && bond_in_place(a, b).is_none() => {
                out.insert(name.clone());
            }
            _ => {}
        }
    }
    // Cascade to VLAN children; each pass adds at least one name or stops.
    for _ in 0..=from.interfaces.len() {
        let more: Vec<IfName> = from
            .interfaces
            .values()
            .filter(|i| !out.contains(&i.name))
            .filter(
                |i| matches!(&i.kind, InterfaceKind::Vlan { parent, .. } if out.contains(parent)),
            )
            .map(|i| i.name.clone())
            .collect();
        if more.is_empty() {
            break;
        }
        out.extend(more);
    }
    Ok(out)
}

/// The ordered operations that take the kernel from `from` to `to`.
pub fn plan(from: &Config, to: &Config) -> Result<Vec<Op>, HalError> {
    let doomed = doomed(from, to)?;
    // Links of `to` created by this plan: new virtual links and recreated ones.
    let fresh: BTreeSet<&IfName> = to
        .interfaces
        .values()
        .filter(|i| LinkSpec::of(&i.kind).is_some())
        .filter(|i| !from.interfaces.contains_key(&i.name) || doomed.contains(&i.name))
        .map(|i| &i.name)
        .collect();
    // State of `from` that survives into the build phase.
    let kept = |name: &IfName| from.interfaces.contains_key(name) && !doomed.contains(name);

    // Kept links whose master (bridge or VRF) changes, or whose master is
    // itself deleted or recreated. Enslaving to a VRF cycles the link, which
    // drops its IPv6 addresses, so their addresses are re-added too.
    let remastered: BTreeSet<IfName> = from
        .interfaces
        .keys()
        .filter(|n| kept(n) && to.interfaces.contains_key(*n))
        .filter(|n| {
            let (a, b) = (master(from, n), master(to, n));
            a != b || a.is_some_and(|m| !kept(m))
        })
        .cloned()
        .collect();

    let old_addrs = active_addresses(from);
    let new_addrs = active_addresses(to);
    let rebuilt = rebuilt_links(from, &doomed, &fresh, &remastered, &old_addrs, &new_addrs);

    let mut ops = Vec::new();

    // 0. Routes that go away, or whose link is rebuilt.
    let old_routes = kernel_routes(from);
    let new_routes = kernel_routes(to);
    for r in &old_routes {
        if rebuilt.contains(&r.link) || !new_routes.contains(r) {
            ops.push(Op::DelRoute(r.clone()));
        }
    }

    // 1. Addresses that go away.
    for (link, addr) in &old_addrs {
        if doomed.contains(link)
            || remastered.contains(link)
            || !new_addrs.contains(&(link.clone(), *addr))
        {
            ops.push(Op::DelAddress {
                link: link.clone(),
                addr: *addr,
            });
        }
    }

    // 2. Ports and members that leave (or change) their bridge or VRF.
    let mut detached = BTreeSet::new();
    for old in from.interfaces.values() {
        let stays = kept(&old.name)
            && to.interfaces.contains_key(&old.name)
            && !remastered.contains(&old.name);
        if master(from, &old.name).is_some() && !stays {
            ops.push(Op::SetMaster {
                link: old.name.clone(),
                master: None,
            });
            if old.bond.is_some() {
                detached.insert(&old.name);
            }
        }
    }

    // 3. Delete, VLAN children first.
    let mut dels: Vec<&IfName> = doomed.iter().collect();
    dels.sort_by_key(|n| std::cmp::Reverse(depth(from, n)));
    for name in dels {
        if let Some(spec) = from
            .interfaces
            .get(name)
            .and_then(|i| LinkSpec::of(&i.kind))
        {
            ops.push(Op::DeleteLink {
                link: name.clone(),
                spec,
            });
        }
    }

    // 4. Create, parents first.
    let mut adds: Vec<&IfName> = fresh.iter().copied().collect();
    adds.sort_by_key(|n| depth(to, n));
    for name in adds {
        if let Some(spec) = to.interfaces.get(name).and_then(|i| LinkSpec::of(&i.kind)) {
            ops.push(Op::CreateLink {
                link: name.clone(),
                spec,
            });
        }
    }

    // 4b. Bond settings the kernel changes on the live bond (G1.8d).
    for new in to.interfaces.values() {
        if !kept(&new.name) {
            continue;
        }
        let old = from
            .interfaces
            .get(&new.name)
            .and_then(|i| LinkSpec::of(&i.kind));
        let (Some(old), Some(spec)) = (old, LinkSpec::of(&new.kind)) else {
            continue;
        };
        if bond_in_place(&old, &spec).is_some_and(|s| !s.is_empty()) {
            ops.push(Op::SetBond {
                link: new.name.clone(),
                from: old,
                to: spec,
            });
        }
    }

    // 5. MTU. Unknown old value (new port, fresh link) counts as "increase";
    //    the executor skips a change that is already in place.
    let mut down = Vec::new();
    let mut up = Vec::new();
    for new in to.interfaces.values() {
        let old = from
            .interfaces
            .get(&new.name)
            .filter(|_| kept(&new.name))
            .map(|i| i.mtu);
        match old {
            Some(o) if o == new.mtu => {}
            Some(o) if new.mtu < o => down.push((depth(to, &new.name), new)),
            _ => up.push((depth(to, &new.name), new)),
        }
    }
    down.sort_by_key(|(d, _)| std::cmp::Reverse(*d));
    up.sort_by_key(|(d, _)| *d);
    for (_, i) in down.into_iter().chain(up) {
        ops.push(Op::SetMtu {
            link: i.name.clone(),
            mtu: u32::from(i.mtu),
        });
    }

    // 6. Ports and members that join (or change) their bridge or VRF.
    let mut attached = BTreeSet::new();
    for new in to.interfaces.values() {
        let Some(m) = master(to, &new.name) else {
            continue;
        };
        if !kept(&new.name) || remastered.contains(&new.name) {
            ops.push(Op::SetMaster {
                link: new.name.clone(),
                master: Some(m.clone()),
            });
            if new.bond.is_some() {
                attached.insert(&new.name);
            }
        }
    }

    // 7. Addresses that arrive (or whose link was recreated or remastered).
    for (link, addr) in &new_addrs {
        if fresh.contains(link)
            || remastered.contains(link)
            || !old_addrs.contains(&(link.clone(), *addr))
        {
            ops.push(Op::AddAddress {
                link: link.clone(),
                addr: *addr,
            });
        }
    }

    // 8. Admin state, parents first. A bond brings a slave up when it takes
    //    it and leaves it down when it lets it go, so a link that joined or
    //    left a bond gets its state again.
    let mut states: Vec<(usize, &IfName, bool)> = to
        .interfaces
        .values()
        .filter(|new| {
            fresh.contains(&new.name)
                || attached.contains(&new.name)
                || detached.contains(&new.name)
                || from
                    .interfaces
                    .get(&new.name)
                    .is_none_or(|old| old.disabled != new.disabled)
        })
        .map(|i| (depth(to, &i.name), &i.name, !i.disabled))
        .collect();
    states.sort_by_key(|(d, _, _)| *d);
    for (_, name, up) in states {
        ops.push(Op::SetUp {
            link: name.clone(),
            up,
        });
    }

    // 9. Routes that arrive, or whose link was rebuilt.
    for r in &new_routes {
        if rebuilt.contains(&r.link) || !old_routes.contains(r) {
            ops.push(Op::AddRoute(r.clone()));
        }
    }

    Ok(ops)
}

/// The operations that put back what `cfg` (the applied config) holds in
/// the kernel, where `have` (read from it) drifted (G1.3). Same phase order
/// as [`plan`]; a missing virtual link is created again with its MTU,
/// master, addresses, state and routes, a missing port is left alone. The
/// executor skips what is already in place, and the engine checks again
/// afterwards: enslaving to a VRF, for one, drops addresses that the next
/// round puts back.
pub fn repair(cfg: &Config, have: &Snapshot) -> Vec<Op> {
    let want = drift::expected(cfg);
    let fresh: BTreeSet<&IfName> = want
        .links
        .keys()
        .filter(|n| !have.links.contains_key(*n) && drift::recreatable(cfg, n))
        .collect();
    let there = |l: &IfName| have.links.contains_key(l) || fresh.contains(l);
    let mut ops = Vec::new();

    // Teardown: what the kernel has on our links and the config does not.
    for r in have.routes.difference(&want.routes) {
        if want.links.contains_key(&r.link) {
            ops.push(Op::DelRoute(r.clone()));
        }
    }
    for (link, addr) in have.addresses.difference(&want.addresses) {
        let link_local = matches!(addr, IpNet::V6(v6) if v6.addr().is_unicast_link_local());
        if want.links.contains_key(link) && !link_local {
            ops.push(Op::DelAddress {
                link: link.clone(),
                addr: *addr,
            });
        }
    }

    // Create, parents first.
    let mut adds: Vec<&IfName> = fresh.iter().copied().collect();
    adds.sort_by_key(|n| depth(cfg, n));
    for name in adds {
        if let Some(spec) = cfg.interfaces.get(name).and_then(|i| LinkSpec::of(&i.kind)) {
            ops.push(Op::CreateLink {
                link: name.clone(),
                spec,
            });
        }
    }

    // MTU: decreases children first, then increases parents first.
    let (mut down, mut up) = (Vec::new(), Vec::new());
    for (name, w) in &want.links {
        match have.links.get(name).map(|h| h.mtu) {
            Some(m) if m == w.mtu => {}
            Some(m) if w.mtu < m => down.push((depth(cfg, name), name, w.mtu)),
            Some(_) => up.push((depth(cfg, name), name, w.mtu)),
            None if fresh.contains(name) => up.push((depth(cfg, name), name, w.mtu)),
            None => {}
        }
    }
    down.sort_by_key(|(d, _, _)| std::cmp::Reverse(*d));
    up.sort_by_key(|(d, _, _)| *d);
    for (_, name, mtu) in down.into_iter().chain(up) {
        ops.push(Op::SetMtu {
            link: name.clone(),
            mtu,
        });
    }

    // Bridge / VRF membership.
    for (name, w) in &want.links {
        let wrong = match have.links.get(name) {
            Some(h) => h.master != w.master,
            None => fresh.contains(name) && w.master.is_some(),
        };
        if wrong {
            ops.push(Op::SetMaster {
                link: name.clone(),
                master: w.master.clone(),
            });
        }
    }

    for (link, addr) in want.addresses.difference(&have.addresses) {
        if there(link) {
            ops.push(Op::AddAddress {
                link: link.clone(),
                addr: *addr,
            });
        }
    }

    // Admin state, parents first.
    let mut states: Vec<(usize, &IfName, bool)> = want
        .links
        .iter()
        .filter(|(n, w)| match have.links.get(*n) {
            Some(h) => h.up != w.up,
            None => fresh.contains(n),
        })
        .map(|(n, w)| (depth(cfg, n), n, w.up))
        .collect();
    states.sort_by_key(|(d, _, _)| *d);
    for (_, name, up) in states {
        ops.push(Op::SetUp {
            link: name.clone(),
            up,
        });
    }

    for r in want.routes.difference(&have.routes) {
        if there(&r.link) {
            ops.push(Op::AddRoute(r.clone()));
        }
    }
    ops
}

/// Links whose static routes the kernel drops on its own during this plan.
/// (A link going down is not listed: its routes stop being usable, so they
/// leave `kernel_routes` anyway.)
fn rebuilt_links(
    from: &Config,
    doomed: &BTreeSet<IfName>,
    fresh: &BTreeSet<&IfName>,
    remastered: &BTreeSet<IfName>,
    old_addrs: &BTreeSet<(IfName, IpNet)>,
    new_addrs: &BTreeSet<(IfName, IpNet)>,
) -> BTreeSet<IfName> {
    // Links with an IPv4 address, once per set (a scan of every address
    // per interface was O(links × addresses)).
    let v4_links = |set: &'_ BTreeSet<(IfName, IpNet)>| -> BTreeSet<IfName> {
        set.iter()
            .filter(|(_, a)| matches!(a, IpNet::V4(_)))
            .map(|(l, _)| l.clone())
            .collect()
    };
    let (had_v4, has_v4) = (v4_links(old_addrs), v4_links(new_addrs));
    let mut out: BTreeSet<IfName> = doomed.iter().chain(remastered).cloned().collect();
    out.extend(fresh.iter().map(|n| (*n).clone()));
    // Linux disables IPv4 on a link that loses its last IPv4 address,
    // flushing every IPv4 route through it.
    out.extend(
        from.interfaces
            .keys()
            .filter(|l| had_v4.contains(*l) && !has_v4.contains(*l))
            .cloned(),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::{AddressEntry, Interface, ItemId, RouteEntry, RoutingTable, VlanId};

    fn n(s: &str) -> IfName {
        s.parse().unwrap()
    }

    fn eth(cfg: &mut Config, name: &str) {
        cfg.interfaces
            .insert(n(name), Interface::new(n(name), InterfaceKind::Ethernet));
    }

    fn add(cfg: &mut Config, name: &str, kind: InterfaceKind) {
        cfg.interfaces
            .insert(n(name), Interface::new(n(name), kind));
    }

    fn vlan(parent: &str, id: u16) -> InterfaceKind {
        InterfaceKind::Vlan {
            parent: n(parent),
            vlan_id: VlanId::new(id).unwrap(),
        }
    }

    fn addr(cfg: &mut Config, iface: &str, a: &str) {
        let id = cfg.ip.next_address_id();
        cfg.ip.addresses.push(AddressEntry {
            id,
            address: a.parse().unwrap(),
            interface: n(iface),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
    }

    fn route(cfg: &mut Config, dst: &str, gw: &str, distance: u8) {
        let id = cfg.ip.next_route_id();
        cfg.ip.routes.push(RouteEntry {
            id,
            dst_address: dst.parse().unwrap(),
            gateway: gw.parse().unwrap(),
            distance,
            routing_table: RoutingTable::Main,
            disabled: false,
            comment: String::new(),
        });
    }

    fn kr(dst: &str, gw: Option<&str>, link: &str, metric: u32, table: u32) -> KernelRoute {
        KernelRoute {
            table,
            dst: dst.parse().unwrap(),
            metric,
            link: n(link),
            gateway: gw.map(|g| g.parse().unwrap()),
        }
    }

    fn base() -> Config {
        let mut c = Config::default();
        eth(&mut c, "ether1");
        eth(&mut c, "ether2");
        c
    }

    fn pos(ops: &[Op], want: &Op) -> usize {
        ops.iter()
            .position(|o| o == want)
            .unwrap_or_else(|| panic!("missing {want} in {ops:#?}"))
    }

    #[test]
    fn same_config_is_empty_plan() {
        let mut c = base();
        add(&mut c, "vlan10", vlan("ether1", 10));
        addr(&mut c, "vlan10", "10.0.0.1/24");
        assert_eq!(plan(&c, &c).unwrap(), vec![]);
    }

    #[test]
    fn build_order_is_create_ports_addresses_up() {
        let from = base();
        let mut to = base();
        add(&mut to, "br0", InterfaceKind::Bridge);
        add(&mut to, "vlan10", vlan("br0", 10));
        add(&mut to, "lo0", InterfaceKind::Loopback);
        to.interfaces.get_mut(&n("ether2")).unwrap().bridge = Some(n("br0"));
        addr(&mut to, "vlan10", "10.0.0.1/24");
        addr(&mut to, "lo0", "2001:db8::1/128");
        let ops = plan(&from, &to).unwrap();

        let create_br = pos(
            &ops,
            &Op::CreateLink {
                link: n("br0"),
                spec: LinkSpec::Bridge,
            },
        );
        let create_vlan = pos(
            &ops,
            &Op::CreateLink {
                link: n("vlan10"),
                spec: LinkSpec::Vlan {
                    parent: n("br0"),
                    vlan_id: 10,
                },
            },
        );
        let attach = pos(
            &ops,
            &Op::SetMaster {
                link: n("ether2"),
                master: Some(n("br0")),
            },
        );
        let address = pos(
            &ops,
            &Op::AddAddress {
                link: n("vlan10"),
                addr: "10.0.0.1/24".parse().unwrap(),
            },
        );
        let up = pos(
            &ops,
            &Op::SetUp {
                link: n("vlan10"),
                up: true,
            },
        );
        assert!(create_br < create_vlan, "parent before VLAN");
        assert!(create_vlan < attach && attach < address && address < up);
        assert!(ops.contains(&Op::CreateLink {
            link: n("lo0"),
            spec: LinkSpec::Dummy
        }));
        // Physical ports are never created, and untouched ones get no ops.
        assert!(!ops.iter().any(|o| o.link() == &n("ether1")));
        assert!(
            !ops.iter()
                .any(|o| matches!(o, Op::CreateLink { link, .. } if link == &n("ether2")))
        );
    }

    #[test]
    fn teardown_is_the_reverse() {
        let mut from = base();
        add(&mut from, "br0", InterfaceKind::Bridge);
        add(&mut from, "vlan10", vlan("br0", 10));
        add(&mut from, "vlan11", vlan("vlan10", 11));
        from.interfaces.get_mut(&n("ether2")).unwrap().bridge = Some(n("br0"));
        addr(&mut from, "vlan11", "10.1.1.1/24");
        let to = base();
        let ops = plan(&from, &to).unwrap();
        assert_eq!(
            ops,
            vec![
                Op::DelAddress {
                    link: n("vlan11"),
                    addr: "10.1.1.1/24".parse().unwrap()
                },
                Op::SetMaster {
                    link: n("ether2"),
                    master: None
                },
                Op::DeleteLink {
                    link: n("vlan11"),
                    spec: LinkSpec::Vlan {
                        parent: n("vlan10"),
                        vlan_id: 11
                    }
                },
                Op::DeleteLink {
                    link: n("vlan10"),
                    spec: LinkSpec::Vlan {
                        parent: n("br0"),
                        vlan_id: 10
                    }
                },
                Op::DeleteLink {
                    link: n("br0"),
                    spec: LinkSpec::Bridge
                },
            ]
        );
    }

    #[test]
    fn recreating_a_parent_recreates_its_vlans_and_their_addresses() {
        let mut from = base();
        add(&mut from, "vlan10", vlan("ether1", 10));
        add(&mut from, "vlan100", vlan("vlan10", 100));
        addr(&mut from, "vlan100", "10.0.0.1/24");
        let mut to = from.clone();
        // Same name, new VLAN id: the kernel cannot change it in place.
        to.interfaces.get_mut(&n("vlan10")).unwrap().kind = vlan("ether1", 20);
        let ops = plan(&from, &to).unwrap();
        let a: IpNet = "10.0.0.1/24".parse().unwrap();
        let del_addr = pos(
            &ops,
            &Op::DelAddress {
                link: n("vlan100"),
                addr: a,
            },
        );
        let del_child = pos(
            &ops,
            &Op::DeleteLink {
                link: n("vlan100"),
                spec: LinkSpec::Vlan {
                    parent: n("vlan10"),
                    vlan_id: 100,
                },
            },
        );
        let del_parent = pos(
            &ops,
            &Op::DeleteLink {
                link: n("vlan10"),
                spec: LinkSpec::Vlan {
                    parent: n("ether1"),
                    vlan_id: 10,
                },
            },
        );
        let add_parent = pos(
            &ops,
            &Op::CreateLink {
                link: n("vlan10"),
                spec: LinkSpec::Vlan {
                    parent: n("ether1"),
                    vlan_id: 20,
                },
            },
        );
        let add_child = pos(
            &ops,
            &Op::CreateLink {
                link: n("vlan100"),
                spec: LinkSpec::Vlan {
                    parent: n("vlan10"),
                    vlan_id: 100,
                },
            },
        );
        let add_addr = pos(
            &ops,
            &Op::AddAddress {
                link: n("vlan100"),
                addr: a,
            },
        );
        assert!(del_addr < del_child && del_child < del_parent);
        assert!(del_parent < add_parent && add_parent < add_child && add_child < add_addr);
    }

    #[test]
    fn mtu_decreases_children_first_and_increases_parents_first() {
        let mut from = base();
        add(&mut from, "vlan10", vlan("ether1", 10));
        from.interfaces.get_mut(&n("ether1")).unwrap().mtu = 9000;
        from.interfaces.get_mut(&n("vlan10")).unwrap().mtu = 9000;
        let mut to = from.clone();
        to.interfaces.get_mut(&n("ether1")).unwrap().mtu = 1500;
        to.interfaces.get_mut(&n("vlan10")).unwrap().mtu = 1500;
        assert_eq!(
            plan(&from, &to).unwrap(),
            vec![
                Op::SetMtu {
                    link: n("vlan10"),
                    mtu: 1500
                },
                Op::SetMtu {
                    link: n("ether1"),
                    mtu: 1500
                },
            ]
        );
        assert_eq!(
            plan(&to, &from).unwrap(),
            vec![
                Op::SetMtu {
                    link: n("ether1"),
                    mtu: 9000
                },
                Op::SetMtu {
                    link: n("vlan10"),
                    mtu: 9000
                },
            ]
        );
    }

    #[test]
    fn address_changes_are_minimal() {
        let mut from = base();
        addr(&mut from, "ether1", "10.0.0.1/24");
        addr(&mut from, "ether1", "10.0.1.1/24");
        let mut to = base();
        addr(&mut to, "ether1", "10.0.1.1/24");
        addr(&mut to, "ether1", "2001:db8::1/64");
        // Disabled entries and entries on unknown interfaces are ignored.
        addr(&mut to, "ether2", "10.9.9.9/24");
        to.ip.addresses.last_mut().unwrap().disabled = true;
        to.ip.addresses.push(AddressEntry {
            id: ItemId(99),
            address: "10.8.8.8/24".parse().unwrap(),
            interface: n("host0"),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        });
        assert_eq!(
            plan(&from, &to).unwrap(),
            vec![
                Op::DelAddress {
                    link: n("ether1"),
                    addr: "10.0.0.1/24".parse().unwrap()
                },
                Op::AddAddress {
                    link: n("ether1"),
                    addr: "2001:db8::1/64".parse().unwrap()
                },
            ]
        );
    }

    #[test]
    fn admin_state_follows_disabled() {
        let from = base();
        let mut to = base();
        to.interfaces.get_mut(&n("ether2")).unwrap().disabled = true;
        assert_eq!(
            plan(&from, &to).unwrap(),
            vec![Op::SetUp {
                link: n("ether2"),
                up: false
            }]
        );
    }

    #[test]
    fn newly_managed_port_gets_mtu_and_state() {
        // Session::new applies Config::default() → discovered ports.
        let to = base();
        let ops = plan(&Config::default(), &to).unwrap();
        assert!(ops.contains(&Op::SetMtu {
            link: n("ether1"),
            mtu: 1500
        }));
        assert!(ops.contains(&Op::SetUp {
            link: n("ether1"),
            up: true
        }));
        assert!(!ops.iter().any(|o| matches!(o, Op::CreateLink { .. })));
    }

    #[test]
    fn moving_a_port_between_bridges_detaches_then_attaches() {
        let mut from = base();
        add(&mut from, "br0", InterfaceKind::Bridge);
        add(&mut from, "br1", InterfaceKind::Bridge);
        from.interfaces.get_mut(&n("ether1")).unwrap().bridge = Some(n("br0"));
        let mut to = from.clone();
        to.interfaces.get_mut(&n("ether1")).unwrap().bridge = Some(n("br1"));
        assert_eq!(
            plan(&from, &to).unwrap(),
            vec![
                Op::SetMaster {
                    link: n("ether1"),
                    master: None
                },
                Op::SetMaster {
                    link: n("ether1"),
                    master: Some(n("br1"))
                },
            ]
        );
    }

    fn bond(mode: BondMode) -> InterfaceKind {
        InterfaceKind::Bonding {
            mode,
            primary: None,
            transmit_hash_policy: HashPolicy::Layer2,
            lacp_rate: LacpRate::Slow,
            mii_interval_ms: 100,
            min_links: 0,
        }
    }

    #[test]
    fn bond_is_created_then_slaves_join_then_state_is_set() {
        let from = base();
        let mut to = from.clone();
        add(&mut to, "bond1", bond(BondMode::Lacp));
        to.interfaces.get_mut(&n("ether1")).unwrap().bond = Some(n("bond1"));
        to.interfaces.get_mut(&n("ether2")).unwrap().bond = Some(n("bond1"));
        to.interfaces.get_mut(&n("ether2")).unwrap().disabled = true;
        addr(&mut to, "bond1", "10.0.0.1/30");
        let ops = plan(&from, &to).unwrap();
        let at = |op: &Op| ops.iter().position(|o| o == op).unwrap();
        let create = at(&Op::CreateLink {
            link: n("bond1"),
            spec: LinkSpec::of(&bond(BondMode::Lacp)).unwrap(),
        });
        let join = at(&Op::SetMaster {
            link: n("ether1"),
            master: Some(n("bond1")),
        });
        // The kernel opens a slave it takes: a disabled one goes down again.
        let down = at(&Op::SetUp {
            link: n("ether2"),
            up: false,
        });
        let up1 = at(&Op::SetUp {
            link: n("ether1"),
            up: true,
        });
        assert!(create < join && join < down && join < up1, "{ops:?}");
        assert!(ops.contains(&Op::AddAddress {
            link: n("bond1"),
            addr: "10.0.0.1/30".parse().unwrap()
        }));
    }

    #[test]
    fn changing_the_bond_mode_recreates_it_and_rejoins_its_slaves() {
        let mut from = base();
        add(&mut from, "bond1", bond(BondMode::Lacp));
        from.interfaces.get_mut(&n("ether1")).unwrap().bond = Some(n("bond1"));
        let mut to = from.clone();
        to.interfaces.get_mut(&n("bond1")).unwrap().kind = bond(BondMode::ActiveBackup);
        let ops = plan(&from, &to).unwrap();
        let at = |op: &Op| ops.iter().position(|o| o == op).unwrap();
        let leave = at(&Op::SetMaster {
            link: n("ether1"),
            master: None,
        });
        let del = at(&Op::DeleteLink {
            link: n("bond1"),
            spec: LinkSpec::of(&bond(BondMode::Lacp)).unwrap(),
        });
        let create = at(&Op::CreateLink {
            link: n("bond1"),
            spec: LinkSpec::of(&bond(BondMode::ActiveBackup)).unwrap(),
        });
        let join = at(&Op::SetMaster {
            link: n("ether1"),
            master: Some(n("bond1")),
        });
        let up = at(&Op::SetUp {
            link: n("ether1"),
            up: true,
        });
        assert!(
            leave < del && del < create && create < join && join < up,
            "{ops:?}"
        );
    }

    fn tuned(kind: InterfaceKind, f: impl FnOnce(&mut InterfaceKind)) -> InterfaceKind {
        let mut k = kind;
        f(&mut k);
        k
    }

    #[test]
    fn live_bond_settings_change_in_place_without_touching_the_slaves() {
        let mut from = base();
        add(&mut from, "bond1", bond(BondMode::Lacp));
        from.interfaces.get_mut(&n("ether1")).unwrap().bond = Some(n("bond1"));
        addr(&mut from, "bond1", "10.0.0.1/30");
        route(&mut from, "192.0.2.0/24", "10.0.0.2", 1);
        let mut to = from.clone();
        to.interfaces.get_mut(&n("bond1")).unwrap().kind = tuned(bond(BondMode::Lacp), |k| {
            if let InterfaceKind::Bonding {
                mii_interval_ms,
                min_links,
                transmit_hash_policy,
                ..
            } = k
            {
                *mii_interval_ms = 200;
                *min_links = 1;
                *transmit_hash_policy = HashPolicy::Layer34;
            }
        });
        let ops = plan(&from, &to).unwrap();
        let old = LinkSpec::of(&bond(BondMode::Lacp)).unwrap();
        let new = LinkSpec::of(&to.interfaces[&n("bond1")].kind).unwrap();
        assert_eq!(
            ops,
            vec![Op::SetBond {
                link: n("bond1"),
                from: old.clone(),
                to: new.clone(),
            }],
            "no delete, no slave leaving, no route or address reinstalled"
        );
        assert_eq!(
            bond_in_place(&old, &new).unwrap(),
            vec![
                BondSetting::MiiInterval(200),
                BondSetting::MinLinks(1),
                BondSetting::Hash(HashPolicy::Layer34),
            ]
        );
        assert_eq!(
            ops[0].to_string(),
            "set mii-interval 200ms, min-links 1, transmit-hash-policy layer-3-and-4 \
             on bonding 'bond1'"
        );
    }

    #[test]
    fn bond_in_place_needs_the_same_mode_and_lacp_rate() {
        let spec = |k: InterfaceKind| LinkSpec::of(&k).unwrap();
        let lacp = bond(BondMode::Lacp);
        let fast = tuned(lacp.clone(), |k| {
            if let InterfaceKind::Bonding { lacp_rate, .. } = k {
                *lacp_rate = LacpRate::Fast;
            }
        });
        // lacp_rate is BOND_OPTFLAG_IFDOWN, mode NOSLAVES | IFDOWN.
        assert_eq!(bond_in_place(&spec(lacp.clone()), &spec(fast)), None);
        assert_eq!(
            bond_in_place(&spec(lacp.clone()), &spec(bond(BondMode::BalanceXor))),
            None
        );
        assert_eq!(bond_in_place(&spec(lacp), &LinkSpec::Bridge), None);

        // What the mode ignores is no change: no lacp_rate outside 802.3ad,
        // no hash in active-backup, no primary in balance-xor.
        let ab = bond(BondMode::ActiveBackup);
        let ab2 = tuned(ab.clone(), |k| {
            if let InterfaceKind::Bonding {
                lacp_rate,
                transmit_hash_policy,
                primary,
                ..
            } = k
            {
                *lacp_rate = LacpRate::Fast;
                *transmit_hash_policy = HashPolicy::Layer34;
                *primary = Some(n("ether2"));
            }
        });
        assert_eq!(
            bond_in_place(&spec(ab.clone()), &spec(ab2.clone())).unwrap(),
            vec![BondSetting::Primary(Some(n("ether2")))]
        );
        assert_eq!(
            bond_in_place(&spec(ab2), &spec(ab)).unwrap(),
            vec![BondSetting::Primary(None)]
        );
        let xor = bond(BondMode::BalanceXor);
        let xor2 = tuned(xor.clone(), |k| {
            if let InterfaceKind::Bonding { primary, .. } = k {
                *primary = Some(n("ether2"));
            }
        });
        assert_eq!(
            bond_in_place(&spec(xor.clone()), &spec(xor2.clone())).unwrap(),
            vec![]
        );

        // An ignored change plans nothing at all.
        let mut from = base();
        add(&mut from, "bond1", xor);
        let mut to = from.clone();
        to.interfaces.get_mut(&n("bond1")).unwrap().kind = xor2;
        assert_eq!(plan(&from, &to).unwrap(), vec![]);
    }

    #[test]
    fn removing_a_bond_releases_its_slaves_and_brings_them_back_up() {
        let mut from = base();
        add(&mut from, "bond1", bond(BondMode::ActiveBackup));
        from.interfaces.get_mut(&n("ether1")).unwrap().bond = Some(n("bond1"));
        let mut to = from.clone();
        to.interfaces.remove(&n("bond1"));
        to.interfaces.get_mut(&n("ether1")).unwrap().bond = None;
        let ops = plan(&from, &to).unwrap();
        assert_eq!(
            ops.first(),
            Some(&Op::SetMaster {
                link: n("ether1"),
                master: None
            })
        );
        assert!(ops.contains(&Op::SetUp {
            link: n("ether1"),
            up: true
        }));
    }

    #[test]
    fn physical_port_cannot_change_kind() {
        let from = base();
        let mut to = base();
        add(&mut to, "ether1", InterfaceKind::Bridge);
        let err = plan(&from, &to).unwrap_err();
        assert!(err.to_string().contains("physical port"), "{err}");
        let err = plan(&to, &from).unwrap_err();
        assert!(err.to_string().contains("physical port"), "{err}");
    }

    #[test]
    fn cyclic_vlans_do_not_hang() {
        // Validation rejects this, but the planner must still terminate.
        let mut from = base();
        add(&mut from, "a", vlan("b", 1));
        add(&mut from, "b", vlan("a", 2));
        let ops = plan(&from, &base()).unwrap();
        assert_eq!(
            ops.iter()
                .filter(|o| matches!(o, Op::DeleteLink { .. }))
                .count(),
            2
        );
    }

    /// ether1 10.0.0.2/24 + 2001:db8::2/64, default routes via the upstream.
    fn routed() -> Config {
        let mut c = base();
        addr(&mut c, "ether1", "10.0.0.2/24");
        addr(&mut c, "ether1", "2001:db8::2/64");
        route(&mut c, "0.0.0.0/0", "10.0.0.1", 1);
        route(&mut c, "::/0", "2001:db8::1", 1);
        c
    }

    #[test]
    fn routes_come_after_their_address_and_go_before_it() {
        let to = routed();
        let ops = plan(&base(), &to).unwrap();
        let v4 = Op::AddRoute(kr("0.0.0.0/0", Some("10.0.0.1"), "ether1", 1, 254));
        let v6 = Op::AddRoute(kr("::/0", Some("2001:db8::1"), "ether1", 1, 254));
        let address = Op::AddAddress {
            link: n("ether1"),
            addr: "10.0.0.2/24".parse().unwrap(),
        };
        assert!(pos(&ops, &address) < pos(&ops, &v4));
        assert!(pos(&ops, &address) < pos(&ops, &v6));
        assert_eq!(plan(&to, &to).unwrap(), vec![], "nothing to do twice");

        let back = plan(&to, &base()).unwrap();
        let del = Op::DelRoute(kr("0.0.0.0/0", Some("10.0.0.1"), "ether1", 1, 254));
        let del_addr = Op::DelAddress {
            link: n("ether1"),
            addr: "10.0.0.2/24".parse().unwrap(),
        };
        assert!(pos(&back, &del) < pos(&back, &del_addr));
    }

    #[test]
    fn changing_a_route_replaces_only_that_route() {
        let from = routed();
        let mut to = from.clone();
        to.ip.routes.first_mut().unwrap().distance = 5;
        assert_eq!(
            plan(&from, &to).unwrap(),
            vec![
                Op::DelRoute(kr("0.0.0.0/0", Some("10.0.0.1"), "ether1", 1, 254)),
                Op::AddRoute(kr("0.0.0.0/0", Some("10.0.0.1"), "ether1", 5, 254)),
            ]
        );
        // A disabled route leaves the kernel; an interface route needs no address.
        let mut to = from.clone();
        to.ip.routes.first_mut().unwrap().disabled = true;
        route(&mut to, "198.51.100.0/24", "ether2", 3);
        assert_eq!(
            plan(&from, &to).unwrap(),
            vec![
                Op::DelRoute(kr("0.0.0.0/0", Some("10.0.0.1"), "ether1", 1, 254)),
                Op::AddRoute(kr("198.51.100.0/24", None, "ether2", 3, 254)),
            ]
        );
    }

    #[test]
    fn link_down_and_up_removes_and_restores_its_routes() {
        let from = routed();
        let mut down = from.clone();
        down.interfaces.get_mut(&n("ether1")).unwrap().disabled = true;
        let ops = plan(&from, &down).unwrap();
        let del = Op::DelRoute(kr("0.0.0.0/0", Some("10.0.0.1"), "ether1", 1, 254));
        let off = Op::SetUp {
            link: n("ether1"),
            up: false,
        };
        // Removed explicitly before the kernel would flush them, so an undo
        // can bring them back.
        let del6 = Op::DelAddress {
            link: n("ether1"),
            addr: "2001:db8::2/64".parse().unwrap(),
        };
        assert!(pos(&ops, &del) < pos(&ops, &del6) && pos(&ops, &del6) < pos(&ops, &off));
        let ops = plan(&down, &from).unwrap();
        let on = Op::SetUp {
            link: n("ether1"),
            up: true,
        };
        let add = Op::AddRoute(kr("0.0.0.0/0", Some("10.0.0.1"), "ether1", 1, 254));
        let add6 = Op::AddAddress {
            link: n("ether1"),
            addr: "2001:db8::2/64".parse().unwrap(),
        };
        assert!(pos(&ops, &add6) < pos(&ops, &on) && pos(&ops, &on) < pos(&ops, &add));
    }

    #[test]
    fn losing_the_last_ipv4_address_reinstalls_the_links_routes() {
        let mut from = base();
        addr(&mut from, "ether2", "192.0.2.1/24");
        route(&mut from, "198.51.100.0/24", "ether2", 1);
        let mut to = from.clone();
        to.ip.addresses.clear();
        let r = kr("198.51.100.0/24", None, "ether2", 1, 254);
        assert_eq!(
            plan(&from, &to).unwrap(),
            vec![
                Op::DelRoute(r.clone()),
                Op::DelAddress {
                    link: n("ether2"),
                    addr: "192.0.2.1/24".parse().unwrap()
                },
                Op::AddRoute(r),
            ]
        );
    }

    #[test]
    fn joining_a_vrf_moves_addresses_and_routes_to_its_table() {
        let mut from = base();
        addr(&mut from, "ether2", "10.9.0.2/24");
        addr(&mut from, "ether2", "2001:db8:9::2/64");
        let mut to = from.clone();
        add(&mut to, "blue", InterfaceKind::Vrf { table: 1000 });
        to.interfaces.get_mut(&n("ether2")).unwrap().vrf = Some(n("blue"));
        route(&mut to, "10.50.0.0/16", "10.9.0.1", 1);
        to.ip.routes.first_mut().unwrap().routing_table = RoutingTable::Vrf(n("blue"));
        let ops = plan(&from, &to).unwrap();

        let create = pos(
            &ops,
            &Op::CreateLink {
                link: n("blue"),
                spec: LinkSpec::Vrf { table: 1000 },
            },
        );
        let del6 = pos(
            &ops,
            &Op::DelAddress {
                link: n("ether2"),
                addr: "2001:db8:9::2/64".parse().unwrap(),
            },
        );
        let enslave = pos(
            &ops,
            &Op::SetMaster {
                link: n("ether2"),
                master: Some(n("blue")),
            },
        );
        let add6 = pos(
            &ops,
            &Op::AddAddress {
                link: n("ether2"),
                addr: "2001:db8:9::2/64".parse().unwrap(),
            },
        );
        let up = pos(
            &ops,
            &Op::SetUp {
                link: n("blue"),
                up: true,
            },
        );
        let rt = pos(
            &ops,
            &Op::AddRoute(kr("10.50.0.0/16", Some("10.9.0.1"), "ether2", 1, 1000)),
        );
        assert!(del6 < create && create < enslave && enslave < add6 && add6 < up && up < rt);

        // Leaving it: routes out first, VRF gone last.
        let back = plan(&to, &from).unwrap();
        let del_rt = pos(
            &back,
            &Op::DelRoute(kr("10.50.0.0/16", Some("10.9.0.1"), "ether2", 1, 1000)),
        );
        let release = pos(
            &back,
            &Op::SetMaster {
                link: n("ether2"),
                master: None,
            },
        );
        let delete = pos(
            &back,
            &Op::DeleteLink {
                link: n("blue"),
                spec: LinkSpec::Vrf { table: 1000 },
            },
        );
        assert!(del_rt < release && release < delete);
    }

    #[test]
    fn repair_rebuilds_a_missing_vlan_and_fixes_the_rest() {
        let mut c = routed();
        add(&mut c, "v10", vlan("ether2", 10));
        addr(&mut c, "v10", "10.10.0.1/24");
        let mut have = drift::expected(&c);
        assert!(repair(&c, &have).is_empty(), "in sync: nothing to do");

        have.links.remove(&n("v10"));
        have.addresses.retain(|(l, _)| *l != n("v10"));
        let route = kernel_routes(&c).into_iter().next().unwrap();
        have.routes.remove(&route);
        have.addresses
            .insert((n("ether1"), "192.0.2.9/24".parse().unwrap()));
        have.addresses
            .insert((n("ether1"), "fe80::1/64".parse().unwrap()));
        if let Some(l) = have.links.get_mut(&n("ether2")) {
            l.up = false;
        }
        let ops = repair(&c, &have);
        let del = Op::DelAddress {
            link: n("ether1"),
            addr: "192.0.2.9/24".parse().unwrap(),
        };
        let create = Op::CreateLink {
            link: n("v10"),
            spec: LinkSpec::Vlan {
                parent: n("ether2"),
                vlan_id: 10,
            },
        };
        let v10_addr = Op::AddAddress {
            link: n("v10"),
            addr: "10.10.0.1/24".parse().unwrap(),
        };
        let wanted = [
            del.clone(),
            create.clone(),
            Op::SetMtu {
                link: n("v10"),
                mtu: 1500,
            },
            v10_addr.clone(),
            Op::SetUp {
                link: n("ether2"),
                up: true,
            },
            Op::SetUp {
                link: n("v10"),
                up: true,
            },
            Op::AddRoute(route.clone()),
        ];
        for w in &wanted {
            assert!(ops.contains(w), "{w} missing from {ops:?}");
        }
        assert_eq!(ops.len(), wanted.len(), "{ops:?}");
        assert!(pos(&ops, &del) < pos(&ops, &create));
        assert!(pos(&ops, &create) < pos(&ops, &v10_addr));
        assert!(pos(&ops, &v10_addr) < pos(&ops, &Op::AddRoute(route)));
    }

    #[test]
    fn repair_leaves_a_missing_port_alone() {
        let c = routed();
        let mut have = drift::expected(&c);
        have.links.remove(&n("ether1"));
        have.addresses.retain(|(l, _)| *l != n("ether1"));
        have.routes.clear();
        assert_eq!(repair(&c, &have), Vec::new());
    }
}

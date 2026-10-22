//! rtnetlink executor for [`plan::Op`](crate::plan::Op), with undo.
//!
//! rtnetlink is async; the runtime (tokio, current thread) lives only inside
//! [`apply`], so the `Hal` trait stays synchronous.
//!
//! Every op reads the link from the kernel right before changing it and
//! returns the ops that put it back. If op N fails, the undo of ops N-1..0 is
//! run in reverse and the error says what failed and whether the rollback
//! was complete. Ops that are already in effect (MTU equal, address present)
//! are no-ops with no undo, so applying twice is harmless.

use std::fmt::Write as _;
use std::net::IpAddr;

use corerouter_hal::{Features, HalError, NO_VRF};
use corerouter_model::IfName;
use futures_util::TryStreamExt;
use ipnet::IpNet;
use rtnetlink::packet_route::address::AddressMessage;
use rtnetlink::packet_route::link::{
    InfoData, InfoKind, InfoVlan, InfoVrf, LinkAttribute, LinkFlags, LinkInfo, LinkMessage, State,
};
use rtnetlink::packet_route::route::{
    RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope,
};
use rtnetlink::{
    Handle, LinkBridge, LinkDummy, LinkMessageBuilder, LinkUnspec, LinkVlan, LinkVrf,
    RouteMessageBuilder,
};

use crate::owner::KernelLink;
use crate::plan::{KernelRoute, LinkSpec, Op};

/// Bound on one link dump (hostile input: a kernel with more links than
/// this is not one CoreRouter can manage sensibly anyway).
const MAX_LINKS: usize = 65_536;

const ENOENT: i32 = 2;
const ESRCH: i32 = 3;
const EEXIST: i32 = 17;
const ENODEV: i32 = 19;
const EOPNOTSUPP: i32 = 95;
const EADDRNOTAVAIL: i32 = 99;

/// Table of the throwaway VRF link `probe_vrf` makes: far above the ids the
/// engine hands out (`model::route::LAST_VRF_TABLE`).
const PROBE_TABLE: u32 = 0xFFFF_FFF0;
/// Names `probe_vrf` tries before giving up (each taken one is skipped).
const PROBE_TRIES: u32 = 8;

/// Run `ops` against the kernel of the current network namespace.
pub(crate) fn apply(ops: &[Op]) -> Result<(), HalError> {
    if ops.is_empty() {
        return Ok(());
    }
    with_kernel(|k| async move { run(&k, ops).await })
}

/// Every link of the current network namespace (`RTM_GETLINK` dump): the
/// same kernel `apply` writes to, so discovery and apply never disagree
/// (sysfs shows the namespace that mounted `/sys`, not this one).
pub(crate) fn links() -> Result<Vec<KernelLink>, HalError> {
    with_kernel(|k| async move {
        let mut s = k.handle.link().get().execute();
        let mut out = Vec::new();
        while let Some(m) = s
            .try_next()
            .await
            .map_err(|e| HalError::Io(format!("listing links: {}", readable(&e))))?
        {
            if out.len() >= MAX_LINKS {
                return Err(HalError::Io(format!("more than {MAX_LINKS} links")));
            }
            out.push(kernel_link(&m));
        }
        Ok(out)
    })
}

/// A `RTM_NEWLINK` message as [`KernelLink`].
fn kernel_link(m: &LinkMessage) -> KernelLink {
    let flags = m.header.flags;
    let mut l = KernelLink {
        index: m.header.index,
        arphrd: u16::from(m.header.link_layer_type),
        up: flags.contains(LinkFlags::Up),
        ..KernelLink::default()
    };
    let mut oper = None;
    for a in &m.attributes {
        match a {
            LinkAttribute::IfName(n) => l.name.clone_from(n),
            LinkAttribute::Mtu(v) => l.mtu = *v,
            LinkAttribute::Controller(v) if *v != 0 => l.master = Some(*v),
            LinkAttribute::LinkNetNsId(_) => l.peer_elsewhere = true,
            LinkAttribute::OperState(st) => oper = Some(*st),
            LinkAttribute::Address(mac) if mac.len() == 6 && mac.iter().any(|b| *b != 0) => {
                l.mac = Some(
                    mac.iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(":"),
                );
            }
            LinkAttribute::Stats64(st) => {
                l.rx_bytes = st.rx_bytes;
                l.tx_bytes = st.tx_bytes;
                l.rx_packets = st.rx_packets;
                l.tx_packets = st.tx_packets;
            }
            LinkAttribute::LinkInfo(infos) => {
                for i in infos {
                    if let LinkInfo::Kind(k) = i {
                        l.kind = Some(k.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    // Like `ip link`: dummy/loopback report UNKNOWN but carry traffic while
    // up and with carrier (`IFF_LOWER_UP`).
    l.running = match oper {
        Some(State::Up) => true,
        Some(State::Unknown) | None => l.up && flags.contains(LinkFlags::LowerUp),
        Some(_) => false,
    };
    l
}

/// What the kernel of the current network namespace supports. A probe that
/// cannot decide (no `CAP_NET_ADMIN`, no netlink) assumes yes and logs why:
/// `apply` still reports a real failure, with the same text.
pub(crate) fn features() -> Features {
    let vrf = match with_kernel(|k| async move { k.probe_vrf().await.map_err(HalError::Io) }) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("could not probe VRF support ({e}); assuming the kernel has it");
            true
        }
    };
    if !vrf {
        log::warn!("{NO_VRF}: ip.vrf.add is disabled");
    }
    Features { vrf }
}

/// A private current-thread runtime and netlink connection for one call.
fn with_kernel<T, F, Fut>(f: F) -> Result<T, HalError>
where
    F: FnOnce(Kernel) -> Fut,
    Fut: Future<Output = Result<T, HalError>>,
{
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(|e| HalError::Io(format!("netlink runtime: {e}")))?;
    rt.block_on(async {
        let (conn, handle, _) = rtnetlink::new_connection()
            .map_err(|e| HalError::Io(format!("netlink socket: {e}")))?;
        let task = tokio::spawn(conn);
        let out = f(Kernel { handle }).await;
        task.abort();
        out
    })
}

async fn run(k: &Kernel, ops: &[Op]) -> Result<(), HalError> {
    let mut undo: Vec<Vec<Op>> = Vec::with_capacity(ops.len());
    for op in ops {
        match k.exec(op).await {
            Ok(u) => undo.push(u),
            Err(e) => {
                let done = undo.iter().filter(|u| !u.is_empty()).count();
                let mut msg = format!("could not {op}: {e}");
                let failures = rollback(k, undo).await;
                if failures.is_empty() {
                    let _ = write!(msg, "; rolled back {done} earlier change(s)");
                } else {
                    let _ = write!(
                        msg,
                        "; ROLLBACK INCOMPLETE, the kernel may differ from the running config: {}",
                        failures.join("; ")
                    );
                }
                log::warn!("netlink apply failed: {msg}");
                return Err(HalError::Rejected(msg));
            }
        }
    }
    Ok(())
}

/// Undo groups in reverse; keeps going past failures and reports them all.
async fn rollback(k: &Kernel, undo: Vec<Vec<Op>>) -> Vec<String> {
    let mut failures = Vec::new();
    for group in undo.into_iter().rev() {
        for op in group {
            if let Err(e) = k.exec(&op).await {
                failures.push(format!("could not {op}: {e}"));
            }
        }
    }
    failures
}

/// What the kernel says about one link.
#[derive(Debug, Default)]
struct Link {
    index: u32,
    mtu: u32,
    up: bool,
    master: Option<u32>,
    lower: Option<u32>,
    kind: Option<InfoKind>,
    vlan_id: Option<u16>,
    vrf_table: Option<u32>,
}

impl Link {
    fn parse(m: &LinkMessage) -> Self {
        let mut l = Link {
            index: m.header.index,
            up: m.header.flags.contains(LinkFlags::Up),
            ..Link::default()
        };
        for a in &m.attributes {
            match a {
                LinkAttribute::Mtu(v) => l.mtu = *v,
                LinkAttribute::Controller(v) if *v != 0 => l.master = Some(*v),
                LinkAttribute::Link(v) if *v != 0 => l.lower = Some(*v),
                LinkAttribute::LinkInfo(infos) => {
                    for i in infos {
                        match i {
                            LinkInfo::Kind(k) => l.kind = Some(k.clone()),
                            LinkInfo::Data(InfoData::Vlan(v)) => {
                                for x in v {
                                    if let InfoVlan::Id(id) = x {
                                        l.vlan_id = Some(*id);
                                    }
                                }
                            }
                            LinkInfo::Data(InfoData::Vrf(v)) => {
                                for x in v {
                                    if let InfoVrf::TableId(t) = x {
                                        l.vrf_table = Some(*t);
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
                _ => {}
            }
        }
        l
    }

    fn is_kind(&self, spec: &LinkSpec) -> bool {
        let want = match spec {
            LinkSpec::Vlan { .. } => InfoKind::Vlan,
            LinkSpec::Bridge => InfoKind::Bridge,
            LinkSpec::Dummy => InfoKind::Dummy,
            LinkSpec::Vrf { .. } => InfoKind::Vrf,
        };
        self.kind.as_ref() == Some(&want)
    }

    /// Same kind, and the same VLAN id / VRF table: safe to adopt or delete.
    fn matches(&self, spec: &LinkSpec) -> bool {
        self.is_kind(spec)
            && match spec {
                LinkSpec::Vlan { vlan_id, .. } => self.vlan_id == Some(*vlan_id),
                LinkSpec::Vrf { table } => self.vrf_table == Some(*table),
                LinkSpec::Bridge | LinkSpec::Dummy => true,
            }
    }

    fn describe_kind(&self) -> String {
        match &self.kind {
            Some(k) => format!("{k:?}").to_lowercase(),
            None => "a physical/unknown link".into(),
        }
    }
}

fn errno(e: &rtnetlink::Error) -> Option<i32> {
    match e {
        rtnetlink::Error::NetlinkError(m) => Some(m.raw_code().abs()),
        _ => None,
    }
}

fn readable(e: &rtnetlink::Error) -> String {
    match e {
        rtnetlink::Error::NetlinkError(m) => m.to_io().to_string(),
        other => other.to_string(),
    }
}

struct Kernel {
    handle: Handle,
}

impl Kernel {
    async fn find(&self, name: &IfName) -> Result<Option<Link>, String> {
        let mut s = self.handle.link().get().match_name(name.as_str()).execute();
        match s.try_next().await {
            Ok(Some(m)) => Ok(Some(Link::parse(&m))),
            Ok(None) => Ok(None),
            Err(e) if errno(&e) == Some(ENODEV) => Ok(None),
            Err(e) => Err(format!("reading '{name}': {}", readable(&e))),
        }
    }

    async fn require(&self, name: &IfName) -> Result<Link, String> {
        self.find(name)
            .await?
            .ok_or_else(|| format!("interface '{name}' does not exist in the kernel"))
    }

    async fn name_of(&self, index: u32) -> Result<Option<IfName>, String> {
        let mut s = self.handle.link().get().match_index(index).execute();
        match s.try_next().await {
            Ok(Some(m)) => Ok(m.attributes.iter().find_map(|a| match a {
                LinkAttribute::IfName(n) => n.parse().ok(),
                _ => None,
            })),
            Ok(None) => Ok(None),
            Err(e) if errno(&e) == Some(ENODEV) => Ok(None),
            Err(e) => Err(format!("reading link #{index}: {}", readable(&e))),
        }
    }

    async fn set(&self, msg: LinkMessage) -> Result<(), String> {
        self.handle
            .link()
            .set(msg)
            .execute()
            .await
            .map_err(|e| readable(&e))
    }

    /// Run one op; returns the ops that undo it, in execution order.
    async fn exec(&self, op: &Op) -> Result<Vec<Op>, String> {
        match op {
            Op::CreateLink { link, spec } => self.create(link, spec).await,
            Op::DeleteLink { link, spec } => self.delete(link, spec).await,
            Op::SetMtu { link, mtu } => {
                let l = self.require(link).await?;
                if l.mtu == *mtu {
                    return Ok(vec![]);
                }
                self.set(LinkUnspec::new_with_index(l.index).mtu(*mtu).build())
                    .await?;
                Ok(vec![Op::SetMtu {
                    link: link.clone(),
                    mtu: l.mtu,
                }])
            }
            Op::SetMaster { link, master } => {
                let l = self.require(link).await?;
                let want = match master {
                    Some(m) => Some(self.require(m).await?.index),
                    None => None,
                };
                if l.master == want {
                    return Ok(vec![]);
                }
                let old = match l.master {
                    Some(i) => self.name_of(i).await?,
                    None => None,
                };
                let b = LinkUnspec::new_with_index(l.index);
                let msg = match want {
                    Some(i) => b.controller(i).build(),
                    None => b.nocontroller().build(),
                };
                self.set(msg).await?;
                Ok(vec![Op::SetMaster {
                    link: link.clone(),
                    master: old,
                }])
            }
            Op::SetUp { link, up } => {
                let l = self.require(link).await?;
                if l.up == *up {
                    return Ok(vec![]);
                }
                let b = LinkUnspec::new_with_index(l.index);
                let msg = if *up { b.up() } else { b.down() }.build();
                self.set(msg).await?;
                Ok(vec![Op::SetUp {
                    link: link.clone(),
                    up: l.up,
                }])
            }
            Op::AddAddress { link, addr } => self.add_address(link, addr).await,
            Op::DelAddress { link, addr } => self.del_address(link, addr).await,
            Op::AddRoute(r) => self.add_route(r).await,
            Op::DelRoute(r) => self.del_route(r).await,
        }
    }

    async fn create(&self, link: &IfName, spec: &LinkSpec) -> Result<Vec<Op>, String> {
        let parent = match spec {
            LinkSpec::Vlan { parent, .. } => Some(self.require(parent).await?.index),
            LinkSpec::Bridge | LinkSpec::Dummy | LinkSpec::Vrf { .. } => None,
        };
        if let Some(l) = self.find(link).await? {
            // Same link already there (daemon restart): adopt it, nothing to undo.
            let same =
                l.matches(spec) && (!matches!(spec, LinkSpec::Vlan { .. }) || l.lower == parent);
            if same {
                log::info!("netlink: '{link}' already exists as {spec}; adopting it");
                return Ok(vec![]);
            }
            return Err(format!(
                "'{link}' already exists in the kernel as {} and does not match {spec}; \
                 refusing to touch it",
                l.describe_kind()
            ));
        }
        let name = link.as_str();
        let msg = match (spec, parent) {
            (LinkSpec::Vlan { vlan_id, .. }, Some(p)) => LinkVlan::new(name, p, *vlan_id).build(),
            (LinkSpec::Vlan { parent, .. }, None) => {
                return Err(format!("parent '{parent}' of VLAN not found"));
            }
            (LinkSpec::Bridge, _) => LinkMessageBuilder::<LinkBridge>::new(name).build(),
            (LinkSpec::Dummy, _) => LinkMessageBuilder::<LinkDummy>::new(name).build(),
            (LinkSpec::Vrf { table }, _) => LinkVrf::new(name, *table).build(),
        };
        self.handle
            .link()
            .add(msg)
            .execute()
            .await
            .map_err(|e| create_error(spec, errno(&e), readable(&e)))?;
        Ok(vec![Op::DeleteLink {
            link: link.clone(),
            spec: spec.clone(),
        }])
    }

    /// Whether the kernel can create `vrf` links: make a throwaway one under
    /// a name nobody uses and delete it. Existing links are never touched: a
    /// taken name is skipped, and only the link made here is deleted.
    async fn probe_vrf(&self) -> Result<bool, String> {
        for n in 0..PROBE_TRIES {
            let raw = format!("crvrf{:x}{n}", std::process::id());
            let name: IfName = raw.parse().map_err(|e| format!("probe link name: {e}"))?;
            let msg = LinkVrf::new(name.as_str(), PROBE_TABLE).build();
            match self.handle.link().add(msg).execute().await {
                Ok(()) => {}
                Err(e) if errno(&e) == Some(EEXIST) => continue,
                Err(e) => {
                    return vrf_verdict(errno(&e))
                        .ok_or_else(|| format!("creating a probe vrf link: {}", readable(&e)));
                }
            }
            // The kernel took it, so it has VRF. Delete it only if the link
            // under that name is still exactly the probe's.
            let ours = LinkSpec::Vrf { table: PROBE_TABLE };
            match self.find(&name).await? {
                Some(l) if l.matches(&ours) => {
                    if let Err(e) = self.handle.link().del(l.index).execute().await {
                        log::warn!("could not delete the probe link '{name}': {}", readable(&e));
                    }
                }
                _ => log::warn!("probe link '{name}' changed under us; left alone"),
            }
            return Ok(true);
        }
        Err(format!("{PROBE_TRIES} probe link names are all taken"))
    }

    async fn delete(&self, link: &IfName, spec: &LinkSpec) -> Result<Vec<Op>, String> {
        let Some(l) = self.find(link).await? else {
            return Ok(vec![]);
        };
        // Never delete something that is not what the config says we created.
        if !l.matches(spec) {
            return Err(format!(
                "kernel has '{link}' as {}, not {spec}; refusing to delete it",
                l.describe_kind()
            ));
        }
        let master = match l.master {
            Some(i) => self.name_of(i).await?,
            None => None,
        };
        self.handle
            .link()
            .del(l.index)
            .execute()
            .await
            .map_err(|e| readable(&e))?;
        let mut undo = vec![
            Op::CreateLink {
                link: link.clone(),
                spec: spec.clone(),
            },
            Op::SetMtu {
                link: link.clone(),
                mtu: l.mtu,
            },
        ];
        if master.is_some() {
            undo.push(Op::SetMaster {
                link: link.clone(),
                master,
            });
        }
        undo.push(Op::SetUp {
            link: link.clone(),
            up: l.up,
        });
        Ok(undo)
    }

    async fn add_address(&self, link: &IfName, addr: &IpNet) -> Result<Vec<Op>, String> {
        let l = self.require(link).await?;
        match self
            .handle
            .address()
            .add(l.index, addr.addr(), addr.prefix_len())
            .execute()
            .await
        {
            Ok(()) => Ok(vec![Op::DelAddress {
                link: link.clone(),
                addr: *addr,
            }]),
            // Already there: not ours to remove on rollback.
            Err(e) if errno(&e) == Some(EEXIST) => Ok(vec![]),
            Err(e) => Err(readable(&e)),
        }
    }

    async fn del_address(&self, link: &IfName, addr: &IpNet) -> Result<Vec<Op>, String> {
        let Some(l) = self.find(link).await? else {
            return Ok(vec![]);
        };
        let found: Vec<AddressMessage> = self
            .handle
            .address()
            .get()
            .set_link_index_filter(l.index)
            .set_address_filter(addr.addr())
            .set_prefix_length_filter(addr.prefix_len())
            .execute()
            .try_collect()
            .await
            .map_err(|e| format!("listing addresses of '{link}': {}", readable(&e)))?;
        let Some(msg) = found.into_iter().next() else {
            return Ok(vec![]);
        };
        match self.handle.address().del(msg).execute().await {
            Ok(()) => Ok(vec![Op::AddAddress {
                link: link.clone(),
                addr: *addr,
            }]),
            Err(e) if matches!(errno(&e), Some(EADDRNOTAVAIL | ENOENT)) => Ok(vec![]),
            Err(e) => Err(readable(&e)),
        }
    }

    async fn add_route(&self, r: &KernelRoute) -> Result<Vec<Op>, String> {
        let l = self.require(&r.link).await?;
        match self
            .handle
            .route()
            .add(route_msg(r, l.index)?)
            .execute()
            .await
        {
            Ok(()) => Ok(vec![Op::DelRoute(r.clone())]),
            // Exactly ours already (daemon restart): adopt it, nothing to undo.
            Err(e) if errno(&e) == Some(EEXIST) => {
                if self.has_route(r, l.index).await? {
                    Ok(vec![])
                } else {
                    Err(format!(
                        "the kernel already has another route to {} with metric {} in table {}; \
                         refusing to replace it",
                        r.dst, r.metric, r.table
                    ))
                }
            }
            Err(e) => Err(readable(&e)),
        }
    }

    async fn del_route(&self, r: &KernelRoute) -> Result<Vec<Op>, String> {
        // No link, no route: the kernel removed it with the link.
        let Some(l) = self.find(&r.link).await? else {
            return Ok(vec![]);
        };
        match self
            .handle
            .route()
            .del(route_msg(r, l.index)?)
            .execute()
            .await
        {
            Ok(()) => Ok(vec![Op::AddRoute(r.clone())]),
            Err(e) if matches!(errno(&e), Some(ESRCH | ENOENT)) => Ok(vec![]),
            Err(e) => Err(readable(&e)),
        }
    }

    /// Whether the kernel holds `r` exactly (static, same next hop).
    async fn has_route(&self, r: &KernelRoute, oif: u32) -> Result<bool, String> {
        let probe = match r.dst {
            IpNet::V4(_) => RouteMessageBuilder::<std::net::Ipv4Addr>::new().build(),
            IpNet::V6(_) => RouteMessageBuilder::<std::net::Ipv6Addr>::new().build(),
        };
        let all: Vec<RouteMessage> = self
            .handle
            .route()
            .get(probe)
            .execute()
            .try_collect()
            .await
            .map_err(|e| format!("listing routes: {}", readable(&e)))?;
        Ok(all.iter().any(|m| same_route(m, r, oif)))
    }
}

/// Why creating `spec` failed, in words an operator can act on.
fn create_error(spec: &LinkSpec, code: Option<i32>, text: String) -> String {
    match (spec, code) {
        // "Operation not supported": the `vrf` link kind is not in the kernel.
        (LinkSpec::Vrf { .. }, Some(EOPNOTSUPP)) => NO_VRF.to_owned(),
        _ => text,
    }
}

/// The probe's answer for a failed `vrf` create: `Some(false)` when the
/// kernel does not know the kind, `None` when the error says nothing about it.
fn vrf_verdict(code: Option<i32>) -> Option<bool> {
    (code == Some(EOPNOTSUPP)).then_some(false)
}

/// The netlink message that adds or deletes `r` (same fields both ways, so
/// a delete only ever matches the route an add made).
fn route_msg(r: &KernelRoute, oif: u32) -> Result<RouteMessage, String> {
    let b = RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(r.dst.addr(), r.dst.prefix_len())
        .map_err(|e| e.to_string())?
        .output_interface(oif)
        .priority(r.metric)
        .table_id(r.table)
        .protocol(RouteProtocol::Static);
    let b = match r.gateway {
        Some(g) => b.gateway(g).map_err(|e| e.to_string())?,
        // Like `ip route add … dev X`: an on-link route has link scope.
        None if r.dst.addr().is_ipv4() => b.scope(RouteScope::Link),
        None => b,
    };
    Ok(b.build())
}

fn same_route(m: &RouteMessage, r: &KernelRoute, oif: u32) -> bool {
    let h = &m.header;
    let mut table = u32::from(h.table);
    let (mut dst, mut gw, mut out, mut prio) = (None, None, None, 0);
    for a in &m.attributes {
        match a {
            RouteAttribute::Table(t) => table = *t,
            RouteAttribute::Destination(d) => dst = ip_of(d),
            RouteAttribute::Gateway(g) => gw = ip_of(g),
            RouteAttribute::Oif(i) => out = Some(*i),
            RouteAttribute::Priority(p) => prio = *p,
            _ => {}
        }
    }
    let dst_ok = match dst {
        Some(d) => d == r.dst.addr(),
        // The default route carries no RTA_DST.
        None => r.dst.prefix_len() == 0,
    };
    h.protocol == RouteProtocol::Static
        && table == r.table
        && h.destination_prefix_length == r.dst.prefix_len()
        && dst_ok
        && prio == r.metric
        && out == Some(oif)
        && gw == r.gateway
}

fn ip_of(a: &RouteAddress) -> Option<IpAddr> {
    match a {
        RouteAddress::Inet(v4) => Some(IpAddr::V4(*v4)),
        RouteAddress::Inet6(v6) => Some(IpAddr::V6(*v6)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vrf_create_without_kernel_support_says_so() {
        let vrf = LinkSpec::Vrf { table: 1000 };
        let raw = "Operation not supported (os error 95)".to_owned();
        assert_eq!(create_error(&vrf, Some(EOPNOTSUPP), raw.clone()), NO_VRF);
        // Other errors, and EOPNOTSUPP on other kinds, keep the kernel's text.
        assert_eq!(create_error(&vrf, Some(EEXIST), "exists".into()), "exists");
        assert_eq!(
            create_error(&LinkSpec::Bridge, Some(EOPNOTSUPP), raw.clone()),
            raw
        );
        assert_eq!(create_error(&vrf, None, "socket".into()), "socket");
    }

    #[test]
    fn probe_verdict_is_no_only_for_unsupported() {
        assert_eq!(vrf_verdict(Some(EOPNOTSUPP)), Some(false));
        for undecided in [None, Some(1), Some(EEXIST), Some(ENODEV)] {
            assert_eq!(vrf_verdict(undecided), None, "{undecided:?}");
        }
    }
}

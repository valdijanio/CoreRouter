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

use corerouter_hal::HalError;
use corerouter_model::IfName;
use futures_util::TryStreamExt;
use ipnet::IpNet;
use rtnetlink::packet_route::address::AddressMessage;
use rtnetlink::packet_route::link::{
    InfoData, InfoKind, InfoVlan, InfoVrf, LinkAttribute, LinkFlags, LinkInfo, LinkMessage,
};
use rtnetlink::packet_route::route::{
    RouteAddress, RouteAttribute, RouteMessage, RouteProtocol, RouteScope,
};
use rtnetlink::{
    Handle, LinkBridge, LinkDummy, LinkMessageBuilder, LinkUnspec, LinkVlan, LinkVrf,
    RouteMessageBuilder,
};

use crate::plan::{KernelRoute, LinkSpec, Op};

const ENOENT: i32 = 2;
const ESRCH: i32 = 3;
const EEXIST: i32 = 17;
const ENODEV: i32 = 19;
const EADDRNOTAVAIL: i32 = 99;

/// Run `ops` against the kernel of the current network namespace.
pub(crate) fn apply(ops: &[Op]) -> Result<(), HalError> {
    if ops.is_empty() {
        return Ok(());
    }
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .map_err(|e| HalError::Io(format!("netlink runtime: {e}")))?;
    rt.block_on(async {
        let (conn, handle, _) = rtnetlink::new_connection()
            .map_err(|e| HalError::Io(format!("netlink socket: {e}")))?;
        let task = tokio::spawn(conn);
        let out = run(&Kernel { handle }, ops).await;
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
            .map_err(|e| readable(&e))?;
        Ok(vec![Op::DeleteLink {
            link: link.clone(),
            spec: spec.clone(),
        }])
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

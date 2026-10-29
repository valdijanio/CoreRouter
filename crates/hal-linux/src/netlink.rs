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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use corerouter_hal::{Features, HalError, Learned, NO_VRF};
use corerouter_model::{BondMode, HashPolicy, IfName, LacpRate};
use futures_util::{StreamExt, TryStreamExt};
use ipnet::{IpNet, Ipv6Net};
use rtnetlink::packet_route::AddressFamily;
use rtnetlink::packet_route::address::{
    AddressAttribute, AddressFlags, AddressHeaderFlags, AddressMessage, AddressScope,
};
use rtnetlink::packet_route::link::{
    BondLacpRate, BondMode as KBondMode, BondXmitHashPolicy, InfoBond, InfoData, InfoKind,
    InfoVlan, InfoVrf, LinkAttribute, LinkFlags, LinkInfo, LinkMessage, State, VlanProtocol,
};
use rtnetlink::packet_route::route::{
    RouteAddress, RouteAttribute, RouteMessage, RouteNextHop, RouteProtocol, RouteScope,
};
use rtnetlink::{
    AddressMessageBuilder, Handle, LinkBond, LinkBridge, LinkDummy, LinkMessageBuilder, LinkUnspec,
    LinkVeth, LinkVlan, LinkVrf, RouteMessageBuilder,
};

use crate::owner::KernelLink;
use crate::plan::{BondSetting, KernelRoute, LinkSpec, Op, bond_in_place};

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

/// Run `ops` against the kernel of the current network namespace. `owned`
/// are the static routes (per path) CoreRouter puts there, before and
/// after: only those are ever merged into one ECMP route with a new path.
pub(crate) fn apply(
    ops: &[Op],
    owned: &std::collections::BTreeSet<KernelRoute>,
) -> Result<(), HalError> {
    if ops.is_empty() {
        return Ok(());
    }
    with_kernel(|mut k| async move {
        k.owned = owned.clone();
        run(&k, ops).await
    })
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

/// What one link's `RTM_NEWLINK` says beyond [`KernelLink`] (G1.19).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LinkDetail {
    pub link: KernelLink,
    pub perm_mac: Option<String>,
    pub min_mtu: Option<u32>,
    pub max_mtu: Option<u32>,
    pub rx_queues: Option<u32>,
    pub tx_queues: Option<u32>,
    /// `pci` and `0000:03:00.0` for a PCI NIC (kernel ≥ 5.16).
    pub parent_bus: Option<String>,
    pub parent_dev: Option<String>,
    pub carrier_changes: Option<u32>,
    pub carrier_down_count: Option<u32>,
    /// Every `IFLA_STATS64` counter, kernel names.
    pub stats: Vec<(String, u64)>,
}

/// Link `name` of the current network namespace; `Ok(None)` if absent.
pub(crate) fn link_detail(name: &str) -> Result<Option<LinkDetail>, HalError> {
    let name = name.to_owned();
    with_kernel(|k| async move {
        let mut s = k.handle.link().get().match_name(name.clone()).execute();
        match s.try_next().await {
            Ok(Some(m)) => Ok(Some(detail(&m))),
            Ok(None) => Ok(None),
            Err(e) if errno(&e) == Some(ENODEV) => Ok(None),
            Err(e) => Err(HalError::Io(format!(
                "reading link {name}: {}",
                readable(&e)
            ))),
        }
    })
}

fn mac_text(mac: &[u8]) -> Option<String> {
    (mac.len() == 6 && mac.iter().any(|b| *b != 0)).then(|| {
        mac.iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":")
    })
}

fn detail(m: &LinkMessage) -> LinkDetail {
    let mut d = LinkDetail {
        link: kernel_link(m),
        ..LinkDetail::default()
    };
    for a in &m.attributes {
        match a {
            LinkAttribute::PermAddress(mac) => d.perm_mac = mac_text(mac),
            LinkAttribute::MinMtu(v) => d.min_mtu = Some(*v),
            LinkAttribute::MaxMtu(v) => d.max_mtu = Some(*v),
            LinkAttribute::NumRxQueues(v) => d.rx_queues = Some(*v),
            LinkAttribute::NumTxQueues(v) => d.tx_queues = Some(*v),
            LinkAttribute::ParentDevBusName(v) => d.parent_bus = Some(v.clone()),
            LinkAttribute::ParentDevName(v) => d.parent_dev = Some(v.clone()),
            LinkAttribute::CarrierChanges(v) => d.carrier_changes = Some(*v),
            LinkAttribute::CarrierDownCount(v) => d.carrier_down_count = Some(*v),
            LinkAttribute::Stats64(st) => {
                d.stats = [
                    ("rx_bytes", st.rx_bytes),
                    ("tx_bytes", st.tx_bytes),
                    ("rx_packets", st.rx_packets),
                    ("tx_packets", st.tx_packets),
                    ("rx_errors", st.rx_errors),
                    ("tx_errors", st.tx_errors),
                    ("rx_dropped", st.rx_dropped),
                    ("tx_dropped", st.tx_dropped),
                    ("multicast", st.multicast),
                    ("collisions", st.collisions),
                    ("rx_length_errors", st.rx_length_errors),
                    ("rx_over_errors", st.rx_over_errors),
                    ("rx_crc_errors", st.rx_crc_errors),
                    ("rx_frame_errors", st.rx_frame_errors),
                    ("rx_fifo_errors", st.rx_fifo_errors),
                    ("rx_missed_errors", st.rx_missed_errors),
                    ("tx_aborted_errors", st.tx_aborted_errors),
                    ("tx_carrier_errors", st.tx_carrier_errors),
                    ("tx_fifo_errors", st.tx_fifo_errors),
                    ("tx_heartbeat_errors", st.tx_heartbeat_errors),
                    ("tx_window_errors", st.tx_window_errors),
                    ("rx_compressed", st.rx_compressed),
                    ("tx_compressed", st.tx_compressed),
                    ("rx_nohandler", st.rx_nohandler),
                    ("rx_otherhost_dropped", st.rx_otherhost_dropped),
                ]
                .into_iter()
                .map(|(n, v)| (n.to_owned(), v))
                .collect();
            }
            _ => {}
        }
    }
    d
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
            LinkAttribute::Address(mac) if mac_text(mac).is_some() => l.mac = mac_text(mac),
            LinkAttribute::Stats64(st) => {
                l.rx_bytes = st.rx_bytes;
                l.tx_bytes = st.tx_bytes;
                l.rx_packets = st.rx_packets;
                l.tx_packets = st.tx_packets;
                l.errors = Some(corerouter_hal::LinkErrors {
                    rx_errors: st.rx_errors,
                    tx_errors: st.tx_errors,
                    rx_dropped: st.rx_dropped,
                    tx_dropped: st.tx_dropped,
                });
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
    let mpls = crate::mpls::available();
    if !mpls {
        log::info!(
            "{}: the MPLS commands are disabled",
            corerouter_hal::mpls::NO_MPLS
        );
    }
    Features { vrf, mpls }
}

/// Bound on one address or route dump (hostile input; **estimado**).
const MAX_DUMP: usize = 1 << 20;

/// What the kernel learned from Router Advertisements on the links of
/// `names` (index → name): global IPv6 addresses it made itself (no
/// `IFA_F_PERMANENT`: SLAAC, temporary) and routes of protocol `ra`.
pub(crate) fn learned(
    names: &std::collections::BTreeMap<u32, IfName>,
) -> Result<Vec<Learned>, HalError> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    with_kernel(|k| async move { k.learned(names).await.map_err(HalError::Io) })
}

/// The addresses on the links of `names` the kernel holds in a state other
/// than plainly usable: tentative or failed DAD, deprecated (G1.28).
pub(crate) fn address_states(
    names: &std::collections::BTreeMap<u32, IfName>,
) -> Result<Vec<corerouter_hal::address_state::AddressState>, HalError> {
    if names.is_empty() {
        return Ok(Vec::new());
    }
    with_kernel(|k| async move {
        let all = k.addresses_v6().await.map_err(HalError::Io)?;
        Ok(all
            .iter()
            .filter_map(|m| {
                let interface = names.get(&m.header.index)?.clone();
                address_state(m, interface)
            })
            .collect())
    })
}

/// Remove what [`learned`] would show on `links`, except addresses in
/// `keep` (the config's own). Returns how many entries went.
pub(crate) fn flush_learned(links: &[IfName], keep: &[(IfName, IpNet)]) -> Result<usize, HalError> {
    with_kernel(|k| async move { k.flush_learned(links, keep).await.map_err(HalError::Io) })
}

/// Addresses and static routes the kernel holds on the links of `names`
/// (index → name), for the drift check (G1.3). Addresses the kernel made
/// itself (no `IFA_F_PERMANENT`: SLAAC, temporary) are left out; so are
/// routes of any protocol but `static`, the one `apply` installs with.
#[allow(clippy::type_complexity)]
pub(crate) fn held(
    names: &std::collections::BTreeMap<u32, IfName>,
) -> Result<
    (
        std::collections::BTreeSet<(IfName, IpNet)>,
        std::collections::BTreeSet<KernelRoute>,
    ),
    HalError,
> {
    if names.is_empty() {
        return Ok(Default::default());
    }
    with_kernel(|k| async move { k.held(names).await.map_err(HalError::Io) })
}

/// `ip route get <dst> [from <src>] table <t>` (G1.27).
pub(crate) fn route_get(
    q: &corerouter_hal::route_get::RouteQuery,
) -> Result<corerouter_hal::route_get::KernelLookup, HalError> {
    with_kernel(|k| async move { k.route_get(q).await.map_err(HalError::Io) })
}

/// A configured (permanent) address of `m`, as a prefix.
fn configured_address(m: &AddressMessage) -> Option<IpNet> {
    let mut permanent = m.header.flags.contains(AddressHeaderFlags::Permanent);
    let (mut local, mut address) = (None, None);
    for a in &m.attributes {
        match a {
            // IPv4: IFA_LOCAL is ours, IFA_ADDRESS the peer on a
            // point-to-point link (and the same as IFA_LOCAL otherwise).
            AddressAttribute::Local(ip) => local = Some(*ip),
            AddressAttribute::Address(ip) => address = Some(*ip),
            AddressAttribute::Flags(f) => permanent |= f.contains(AddressFlags::Permanent),
            _ => {}
        }
    }
    if !permanent {
        return None;
    }
    IpNet::new(local.or(address)?, m.header.prefix_len).ok()
}

/// The static unicast route of `m` as one entry per next hop (a multipath
/// route has several), given the link names by index.
fn static_routes(
    m: &RouteMessage,
    names: &std::collections::BTreeMap<u32, IfName>,
) -> Vec<KernelRoute> {
    let h = &m.header;
    if h.protocol != RouteProtocol::Static {
        return Vec::new();
    }
    let mut table = u32::from(h.table);
    let (mut dst, mut gateway, mut oif, mut metric) = (None, None, None, 0);
    let mut multipath: &[RouteNextHop] = &[];
    for a in &m.attributes {
        match a {
            RouteAttribute::Table(t) => table = *t,
            RouteAttribute::Destination(d) => dst = ip_of(d),
            RouteAttribute::Gateway(g) => gateway = ip_of(g),
            RouteAttribute::Oif(i) => oif = Some(*i),
            RouteAttribute::Priority(p) => metric = *p,
            RouteAttribute::MultiPath(hops) => multipath = hops,
            _ => {}
        }
    }
    // The default route carries no RTA_DST.
    let dst = match (dst, h.address_family) {
        (Some(d), _) => d,
        (None, AddressFamily::Inet) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        (None, AddressFamily::Inet6) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        (None, _) => return Vec::new(),
    };
    let Ok(dst) = IpNet::new(dst, h.destination_prefix_length) else {
        return Vec::new();
    };
    let hop = |index: u32, gateway: Option<IpAddr>| {
        Some(KernelRoute {
            table,
            dst,
            metric,
            link: names.get(&index)?.clone(),
            gateway,
        })
    };
    if multipath.is_empty() {
        return oif.and_then(|i| hop(i, gateway)).into_iter().collect();
    }
    multipath
        .iter()
        .filter_map(|nh| {
            let gw = nh.attributes.iter().find_map(|a| match a {
                RouteAttribute::Gateway(g) => ip_of(g),
                _ => None,
            });
            hop(nh.interface_index, gw)
        })
        .collect()
}

fn infinite_or(secs: u32) -> Option<u32> {
    (secs != u32::MAX).then_some(secs)
}

/// A global address the kernel configured itself, as (address, valid, preferred).
fn self_made(m: &AddressMessage) -> Option<(Ipv6Net, Option<u32>, Option<u32>)> {
    if m.header.family != AddressFamily::Inet6 || m.header.scope != AddressScope::Universe {
        return None;
    }
    let mut addr = None;
    let mut permanent = m.header.flags.contains(AddressHeaderFlags::Permanent);
    let mut life = (None, None);
    for a in &m.attributes {
        match a {
            AddressAttribute::Address(IpAddr::V6(v6)) => addr = Some(*v6),
            AddressAttribute::Flags(f) => permanent |= f.contains(AddressFlags::Permanent),
            AddressAttribute::CacheInfo(c) => {
                life = (infinite_or(c.ifa_valid), infinite_or(c.ifa_preferred));
            }
            _ => {}
        }
    }
    if permanent {
        return None;
    }
    let net = Ipv6Net::new(addr?, m.header.prefix_len).ok()?;
    Some((net, life.0, life.1))
}

/// The state of one IPv6 address, when it is not plainly usable.
fn address_state(
    m: &AddressMessage,
    interface: IfName,
) -> Option<corerouter_hal::address_state::AddressState> {
    let h = &m.header.flags;
    let (mut tentative, mut dad_failed, mut deprecated) = (
        h.contains(AddressHeaderFlags::Tentative),
        h.contains(AddressHeaderFlags::Dadfailed),
        h.contains(AddressHeaderFlags::Deprecated),
    );
    let (mut addr, mut life) = (None, (None, None));
    for a in &m.attributes {
        match a {
            AddressAttribute::Address(ip) => addr = Some(*ip),
            AddressAttribute::Flags(f) => {
                tentative |= f.contains(AddressFlags::Tentative);
                dad_failed |= f.contains(AddressFlags::Dadfailed);
                deprecated |= f.contains(AddressFlags::Deprecated);
            }
            AddressAttribute::CacheInfo(c) => {
                life = (infinite_or(c.ifa_valid), infinite_or(c.ifa_preferred));
            }
            _ => {}
        }
    }
    if !(tentative || dad_failed || deprecated) {
        return None;
    }
    Some(corerouter_hal::address_state::AddressState {
        interface,
        address: IpNet::new(addr?, m.header.prefix_len).ok()?,
        tentative,
        dad_failed,
        deprecated,
        valid_secs: life.0,
        preferred_secs: life.1,
    })
}

/// An RA route, as (destination, gateway, oif, metric, table, expires).
#[allow(clippy::type_complexity)]
fn ra_route(m: &RouteMessage) -> Option<(Ipv6Net, Option<Ipv6Addr>, u32, u32, u32, Option<u32>)> {
    let h = &m.header;
    if h.protocol != RouteProtocol::Ra {
        return None;
    }
    let mut table = u32::from(h.table);
    let (mut dst, mut gw, mut oif, mut prio, mut expires) = (None, None, None, 0, None);
    for a in &m.attributes {
        match a {
            RouteAttribute::Table(t) => table = *t,
            RouteAttribute::Destination(RouteAddress::Inet6(d)) => dst = Some(*d),
            RouteAttribute::Gateway(RouteAddress::Inet6(g)) => gw = Some(*g),
            RouteAttribute::Oif(i) => oif = Some(*i),
            RouteAttribute::Priority(p) => prio = *p,
            // Hundredths of a second.
            RouteAttribute::CacheInfo(c) if c.expires > 0 => expires = Some(c.expires / 100),
            _ => {}
        }
    }
    let dst = Ipv6Net::new(
        dst.unwrap_or(Ipv6Addr::UNSPECIFIED),
        h.destination_prefix_length,
    )
    .ok()?;
    Some((dst, gw, oif?, prio, table, expires))
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
        let out = f(Kernel {
            handle,
            hops: std::cell::RefCell::new(None),
            owned: std::collections::BTreeSet::new(),
        })
        .await;
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
    /// TPID 0x88a8 (802.1ad); absent or 0x8100 is plain 802.1Q.
    vlan_service_tag: bool,
    vrf_table: Option<u32>,
    bond_mode: Option<KBondMode>,
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
                                    match x {
                                        InfoVlan::Id(id) => l.vlan_id = Some(*id),
                                        InfoVlan::Protocol(p) => {
                                            l.vlan_service_tag = *p == VlanProtocol::Ieee8021Ad;
                                        }
                                        _ => {}
                                    }
                                }
                            }
                            LinkInfo::Data(InfoData::Bond(v)) => {
                                for x in v {
                                    if let InfoBond::Mode(m) = x {
                                        l.bond_mode = Some(*m);
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
            LinkSpec::Bond { .. } => InfoKind::Bond,
            LinkSpec::PppoeOut { .. } => InfoKind::Veth,
        };
        self.kind.as_ref() == Some(&want)
    }

    /// Same kind, and the same VLAN id / VRF table: safe to adopt or delete.
    fn matches(&self, spec: &LinkSpec) -> bool {
        self.is_kind(spec)
            && match spec {
                LinkSpec::Vlan {
                    vlan_id,
                    service_tag,
                    ..
                } => self.vlan_id == Some(*vlan_id) && self.vlan_service_tag == *service_tag,
                LinkSpec::Vrf { table } => self.vrf_table == Some(*table),
                LinkSpec::Bond { mode, .. } => self.bond_mode == Some(kernel_bond_mode(*mode)),
                LinkSpec::Bridge | LinkSpec::Dummy | LinkSpec::PppoeOut { .. } => true,
            }
    }

    fn describe_kind(&self) -> String {
        match &self.kind {
            Some(k) => format!("{k:?}").to_lowercase(),
            None => "a physical/unknown link".into(),
        }
    }
}

fn kernel_bond_mode(m: BondMode) -> KBondMode {
    match m {
        BondMode::BalanceRr => KBondMode::BalanceRr,
        BondMode::ActiveBackup => KBondMode::ActiveBackup,
        BondMode::BalanceXor => KBondMode::BalanceXor,
        BondMode::Broadcast => KBondMode::Broadcast,
        BondMode::Lacp => KBondMode::Ieee8023Ad,
        BondMode::BalanceTlb => KBondMode::BalanceTlb,
        BondMode::BalanceAlb => KBondMode::BalanceAlb,
    }
}

fn kernel_hash(h: HashPolicy) -> BondXmitHashPolicy {
    match h {
        HashPolicy::Layer2 => BondXmitHashPolicy::Layer2,
        HashPolicy::Layer23 => BondXmitHashPolicy::Layer23,
        HashPolicy::Layer34 => BondXmitHashPolicy::Layer34,
        HashPolicy::Encap23 => BondXmitHashPolicy::Encap23,
        HashPolicy::Encap34 => BondXmitHashPolicy::Encap34,
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

/// Static routes per (table, prefix, metric): the paths of one kernel route.
type Paths = std::collections::HashMap<(u32, IpNet, u32), Vec<KernelRoute>>;

fn group_of(r: &KernelRoute) -> (u32, IpNet, u32) {
    (r.table, r.dst, r.metric)
}

struct Kernel {
    handle: Handle,
    /// The kernel's static routes, one entry per next hop, read at the
    /// first route op of a run and kept up to date by the run's own route
    /// ops (G1.27: an ECMP group is one multipath route in the kernel, so
    /// adding or removing one path rewrites the route with its siblings).
    hops: std::cell::RefCell<Option<Paths>>,
    /// Paths that are CoreRouter's (see [`apply`]); another program's
    /// route with the same prefix and metric is never merged with ours.
    owned: std::collections::BTreeSet<KernelRoute>,
}

impl Kernel {
    async fn find(&self, name: &IfName) -> Result<Option<Link>, String> {
        self.find_str(name.as_str()).await
    }

    /// [`Self::find`] for a kernel name the model does not hold (a relay end).
    async fn find_str(&self, name: &str) -> Result<Option<Link>, String> {
        let mut s = self
            .handle
            .link()
            .get()
            .match_name(name.to_owned())
            .execute();
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
            Op::SetBond { link, from, to } => self.set_bond(link, from, to).await,
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
                    Some(m) => Some(self.require(m).await?),
                    None => None,
                };
                if l.master == want.as_ref().map(|w| w.index) {
                    return Ok(vec![]);
                }
                let old = match l.master {
                    Some(i) => self.name_of(i).await?,
                    None => None,
                };
                // "Device can not be enslaved while up": a bond takes a
                // slave only when it is down, and brings it up itself.
                let downed = l.up
                    && want
                        .as_ref()
                        .is_some_and(|w| w.kind == Some(InfoKind::Bond));
                if downed {
                    self.set(LinkUnspec::new_with_index(l.index).down().build())
                        .await?;
                }
                let b = LinkUnspec::new_with_index(l.index);
                let msg = match &want {
                    Some(w) => b.controller(w.index).build(),
                    None => b.nocontroller().build(),
                };
                if let Err(e) = self.set(msg).await {
                    if downed {
                        let up = LinkUnspec::new_with_index(l.index).up().build();
                        if let Err(e2) = self.set(up).await {
                            log::warn!("could not bring '{link}' back up: {e2}");
                        }
                    }
                    return Err(e);
                }
                // Joining or leaving a bond changes the admin state too (a
                // released slave is left down), so undo restores both.
                Ok(vec![
                    Op::SetMaster {
                        link: link.clone(),
                        master: old,
                    },
                    Op::SetUp {
                        link: link.clone(),
                        up: l.up,
                    },
                ])
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
            LinkSpec::Bridge
            | LinkSpec::Dummy
            | LinkSpec::Vrf { .. }
            | LinkSpec::Bond { .. }
            | LinkSpec::PppoeOut { .. } => None,
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
            (
                LinkSpec::Vlan {
                    vlan_id,
                    service_tag,
                    ..
                },
                Some(p),
            ) => {
                let b = LinkVlan::new(name, p, *vlan_id);
                if *service_tag {
                    b.protocol(VlanProtocol::Ieee8021Ad).build()
                } else {
                    b.build()
                }
            }
            (LinkSpec::Vlan { parent, .. }, None) => {
                return Err(format!("parent '{parent}' of VLAN not found"));
            }
            (LinkSpec::Bridge, _) => LinkMessageBuilder::<LinkBridge>::new(name).build(),
            (LinkSpec::Dummy, _) => LinkMessageBuilder::<LinkDummy>::new(name).build(),
            (LinkSpec::Vrf { table }, _) => LinkVrf::new(name, *table).build(),
            // No ARP on a point-to-point link: the relay owns the far end.
            (LinkSpec::PppoeOut { peer }, _) => LinkVeth::new(name, peer).arp(false).build(),
            (
                LinkSpec::Bond {
                    mode,
                    primary,
                    hash,
                    lacp_rate,
                    mii_interval_ms,
                    min_links,
                },
                _,
            ) => {
                let mut b = LinkBond::new(name)
                    .mode(kernel_bond_mode(*mode))
                    .miimon(*mii_interval_ms)
                    .min_links(*min_links);
                if mode.hashes() {
                    b = b.xmit_hash_policy(kernel_hash(*hash));
                }
                if *mode == BondMode::Lacp {
                    b = b.ad_lacp_rate(match lacp_rate {
                        LacpRate::Slow => BondLacpRate::Slow,
                        LacpRate::Fast => BondLacpRate::Fast,
                    });
                }
                // The kernel keeps the name and picks the slave when it joins.
                if let Some(p) = primary.as_ref().filter(|_| mode.has_primary()) {
                    b = b.primary(self.require(p).await?.index);
                }
                b.build()
            }
        };
        self.handle
            .link()
            .add(msg)
            .execute()
            .await
            .map_err(|e| create_error(spec, errno(&e), readable(&e)))?;
        if let LinkSpec::PppoeOut { peer } = spec {
            self.relay_end_up(peer).await?;
        }
        Ok(vec![Op::DeleteLink {
            link: link.clone(),
            spec: spec.clone(),
        }])
    }

    /// The relay end of a PPPoE client's veth up, and quiet: no IPv6
    /// link-local of its own (it never routes), `addrgenmode none` would
    /// need IFLA_AF_SPEC, so the relay simply ignores what the kernel sends.
    async fn relay_end_up(&self, peer: &str) -> Result<(), String> {
        let l = self
            .find_str(peer)
            .await?
            .ok_or_else(|| format!("relay end '{peer}' missing right after creating it"))?;
        self.handle
            .link()
            .change(LinkUnspec::new_with_index(l.index).up().arp(false).build())
            .execute()
            .await
            .map_err(|e| format!("relay end '{peer}' up: {}", readable(&e)))
    }

    /// Bond settings on the live bond, same ifindex, slaves untouched
    /// (G1.8d): only the `IFLA_BOND_*` that change, which the kernel hands
    /// to `bond_changelink`.
    async fn set_bond(
        &self,
        link: &IfName,
        from: &LinkSpec,
        to: &LinkSpec,
    ) -> Result<Vec<Op>, String> {
        let settings = bond_in_place(from, to)
            .ok_or_else(|| format!("'{link}' cannot change from {from} to {to} in place"))?;
        let l = self.require(link).await?;
        if !l.matches(to) {
            return Err(format!(
                "'{link}' is {} in the kernel, not {to}; refusing to touch it",
                l.describe_kind()
            ));
        }
        let mut b =
            LinkMessageBuilder::<LinkBond>::new_with_info_kind(InfoKind::Bond).index(l.index);
        for s in &settings {
            b = match s {
                BondSetting::MiiInterval(ms) => b.miimon(*ms),
                BondSetting::MinLinks(n) => b.min_links(*n),
                BondSetting::Hash(h) => b.xmit_hash_policy(kernel_hash(*h)),
                // The kernel clears the primary for an ifindex it does not know.
                BondSetting::Primary(p) => b.primary(match p {
                    Some(p) => self.require(p).await?.index,
                    None => 0,
                }),
            };
        }
        // RTM_NEWLINK without NLM_F_CREATE: `RTM_SETLINK` ignores IFLA_LINKINFO.
        self.handle
            .link()
            .change(b.build())
            .execute()
            .await
            .map_err(|e| readable(&e))?;
        Ok(vec![Op::SetBond {
            link: link.clone(),
            from: to.clone(),
            to: from.clone(),
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
        // RTM_DELADDR with the address itself: the kernel finds it by
        // (link, local address, prefix length) and answers EADDRNOTAVAIL if
        // it is not there. (Looking it up first was a full RTM_GETADDR dump
        // filtered in userspace, per address: O(n²) to remove n.)
        let msg = match addr.addr() {
            IpAddr::V4(a) => AddressMessageBuilder::<Ipv4Addr>::new()
                .index(l.index)
                .address(a, addr.prefix_len())
                .build(),
            IpAddr::V6(a) => AddressMessageBuilder::<Ipv6Addr>::new()
                .index(l.index)
                .address(a, addr.prefix_len())
                .build(),
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

    async fn route_get(
        &self,
        q: &corerouter_hal::route_get::RouteQuery,
    ) -> Result<corerouter_hal::route_get::KernelLookup, String> {
        use corerouter_hal::route_get::{KernelHop, KernelLookup, RouteKind};
        use rtnetlink::packet_route::route::{RouteFlags, RouteType};
        const ENETUNREACH: i32 = 101;
        const EHOSTUNREACH: i32 = 113;
        let full = if q.dst.is_ipv4() { 32 } else { 128 };
        let ask = |fib_match: bool| -> Result<RouteMessage, String> {
            let b = RouteMessageBuilder::<IpAddr>::new()
                .destination_prefix(q.dst, full)
                .map_err(|e| e.to_string())?
                .table_id(q.table);
            let b = match q.src {
                Some(s) => b.source_prefix(s, full).map_err(|e| e.to_string())?,
                None => b,
            };
            let mut m = b.build();
            m.header.flags |= RouteFlags::LookupTable;
            if fib_match {
                m.header.flags |= RouteFlags::FibMatch;
            }
            Ok(m)
        };
        let unreachable = KernelLookup {
            kind: RouteKind::Unreachable,
            prefix: None,
            hops: Vec::new(),
            src: None,
            table: q.table,
        };
        let get = |m: RouteMessage| async move {
            let mut s = self.handle.route().get(m).execute();
            s.try_next().await
        };
        let resolved = match get(ask(false)?).await {
            Ok(Some(m)) => m,
            Ok(None) => return Ok(unreachable),
            Err(e) if matches!(errno(&e), Some(ENETUNREACH | EHOSTUNREACH)) => {
                return Ok(unreachable);
            }
            Err(e) => return Err(format!("route get {}: {}", q.dst, readable(&e))),
        };
        // The FIB entry itself: its prefix and every path of a multipath.
        let entry = get(ask(true)?).await.ok().flatten();
        let mut src = None;
        let mut table = q.table;
        for a in &resolved.attributes {
            match a {
                RouteAttribute::PrefSource(p) => src = ip_of(p),
                RouteAttribute::Table(t) => table = *t,
                _ => {}
            }
        }
        let kind = match resolved.header.kind {
            RouteType::Local => RouteKind::Local,
            RouteType::Unicast => RouteKind::Unicast,
            _ => RouteKind::Unreachable,
        };
        let from = entry.as_ref().unwrap_or(&resolved);
        let prefix = entry.as_ref().and_then(|m| {
            let dst = m.attributes.iter().find_map(|a| match a {
                RouteAttribute::Destination(d) => ip_of(d),
                _ => None,
            });
            let dst = dst.or_else(|| {
                Some(if q.dst.is_ipv4() {
                    IpAddr::V4(Ipv4Addr::UNSPECIFIED)
                } else {
                    IpAddr::V6(Ipv6Addr::UNSPECIFIED)
                })
            })?;
            IpNet::new(dst, m.header.destination_prefix_length).ok()
        });
        let mut raw: Vec<(u32, Option<IpAddr>)> = Vec::new();
        let (mut oif, mut gw) = (None, None);
        for a in &from.attributes {
            match a {
                RouteAttribute::Oif(i) => oif = Some(*i),
                RouteAttribute::Gateway(g) => gw = ip_of(g),
                RouteAttribute::MultiPath(hops) => {
                    for nh in hops {
                        let g = nh.attributes.iter().find_map(|a| match a {
                            RouteAttribute::Gateway(g) => ip_of(g),
                            _ => None,
                        });
                        raw.push((nh.interface_index, g));
                    }
                }
                _ => {}
            }
        }
        if raw.is_empty()
            && let Some(i) = oif
        {
            raw.push((i, gw));
        }
        let mut hops = Vec::with_capacity(raw.len());
        for (index, gateway) in raw {
            if let Some(interface) = self.name_of(index).await? {
                hops.push(KernelHop { gateway, interface });
            }
        }
        Ok(KernelLookup {
            kind,
            prefix: if kind == RouteKind::Local {
                IpNet::new(q.dst, full).ok()
            } else {
                prefix
            },
            hops,
            src: src.or(if kind == RouteKind::Local {
                Some(q.dst)
            } else {
                None
            }),
            table,
        })
    }

    /// Read the kernel's static routes once per run (see [`Kernel::hops`]).
    async fn load_hops(&self) -> Result<(), String> {
        if self.hops.borrow().is_some() {
            return Ok(());
        }
        let links: Vec<LinkMessage> = self
            .handle
            .link()
            .get()
            .execute()
            .take(MAX_LINKS)
            .try_collect()
            .await
            .map_err(|e| format!("listing links: {}", readable(&e)))?;
        let names: std::collections::BTreeMap<u32, IfName> = links
            .iter()
            .filter_map(|m| {
                let name = m.attributes.iter().find_map(|a| match a {
                    LinkAttribute::IfName(n) => n.parse().ok(),
                    _ => None,
                })?;
                Some((m.header.index, name))
            })
            .collect();
        let (_, routes) = self.held(&names).await?;
        let mut paths = Paths::new();
        for r in routes {
            paths.entry(group_of(&r)).or_default().push(r);
        }
        *self.hops.borrow_mut() = Some(paths);
        Ok(())
    }

    /// The paths the kernel holds of `r`'s route (same table, prefix and
    /// metric), `r` itself included if present.
    async fn siblings(&self, r: &KernelRoute) -> Result<Vec<KernelRoute>, String> {
        self.load_hops().await?;
        Ok(self
            .hops
            .borrow()
            .as_ref()
            .and_then(|p| p.get(&group_of(r)))
            .cloned()
            .unwrap_or_default())
    }

    fn note_hop(&self, r: &KernelRoute, present: bool) {
        if let Some(h) = self.hops.borrow_mut().as_mut() {
            let group = h.entry(group_of(r)).or_default();
            group.retain(|x| x != r);
            if present {
                group.push(r.clone());
            }
        }
    }

    /// Put `paths` (one table, prefix and metric) in the kernel as one
    /// route, replacing what is there: multipath when there are several.
    async fn replace_paths(&self, paths: &[KernelRoute]) -> Result<(), String> {
        let msg = match paths {
            [] => return Ok(()),
            [one] => route_msg(one, self.require(&one.link).await?.index)?,
            many => {
                let mut hops = Vec::with_capacity(many.len());
                for p in many {
                    hops.push(next_hop(p, self.require(&p.link).await?.index));
                }
                multipath_msg(many, hops)?
            }
        };
        self.handle
            .route()
            .add(msg)
            .replace()
            .execute()
            .await
            .map_err(|e| readable(&e))
    }

    async fn add_route(&self, r: &KernelRoute) -> Result<Vec<Op>, String> {
        let l = self.require(&r.link).await?;
        // Before the kernel's routes are read, try the add (it carries
        // NLM_F_EXCL): a new prefix, the usual case, needs no dump of the
        // whole table (76 ms with 60 000 routes, on every commit; G0.31).
        // EEXIST means a route with this prefix, metric and table is
        // there (ours after a restart, an ECMP sibling or someone else's):
        // only then are they read, and the cases below decide.
        if self.hops.borrow().is_none() {
            match self
                .handle
                .route()
                .add(route_msg(r, l.index)?)
                .execute()
                .await
            {
                Ok(()) => return Ok(vec![Op::DelRoute(r.clone())]),
                Err(e) if errno(&e) == Some(EEXIST) => {}
                Err(e) => return Err(readable(&e)),
            }
        }
        let siblings = self.siblings(r).await?;
        if siblings.contains(r) {
            // Exactly ours already (daemon restart): adopt it, nothing to undo.
            return Ok(vec![]);
        }
        if siblings.iter().any(|s| !self.owned.contains(s)) {
            return Err(format!(
                "the kernel already has another route to {} with metric {} in table {}; \
                 refusing to replace it",
                r.dst, r.metric, r.table
            ));
        }
        if !siblings.is_empty() {
            // Another path of an ECMP group: the route gets this one too.
            let mut paths = siblings;
            paths.push(r.clone());
            paths.sort();
            self.replace_paths(&paths).await?;
            self.note_hop(r, true);
            return Ok(vec![Op::DelRoute(r.clone())]);
        }
        match self
            .handle
            .route()
            .add(route_msg(r, l.index)?)
            .execute()
            .await
        {
            Ok(()) => {
                self.note_hop(r, true);
                Ok(vec![Op::DelRoute(r.clone())])
            }
            // Not a static route of ours (another protocol, by hand).
            Err(e) if errno(&e) == Some(EEXIST) => Err(format!(
                "the kernel already has another route to {} with metric {} in table {}; \
                 refusing to replace it",
                r.dst, r.metric, r.table
            )),
            Err(e) => Err(readable(&e)),
        }
    }

    async fn del_route(&self, r: &KernelRoute) -> Result<Vec<Op>, String> {
        // No link, no route: the kernel removed it with the link.
        let Some(l) = self.find(&r.link).await? else {
            self.note_hop(r, false);
            return Ok(vec![]);
        };
        let siblings = self.siblings(r).await?;
        if !siblings.contains(r) {
            return Ok(vec![]);
        }
        if siblings.len() > 1 {
            // One path of an ECMP group leaves: the others stay.
            let rest: Vec<KernelRoute> = siblings.into_iter().filter(|s| s != r).collect();
            self.replace_paths(&rest).await?;
            self.note_hop(r, false);
            return Ok(vec![Op::AddRoute(r.clone())]);
        }
        match self
            .handle
            .route()
            .del(route_msg(r, l.index)?)
            .execute()
            .await
        {
            Ok(()) => {
                self.note_hop(r, false);
                Ok(vec![Op::AddRoute(r.clone())])
            }
            Err(e) if matches!(errno(&e), Some(ESRCH | ENOENT)) => {
                self.note_hop(r, false);
                Ok(vec![])
            }
            Err(e) => Err(readable(&e)),
        }
    }

    async fn addresses_v6(&self) -> Result<Vec<AddressMessage>, String> {
        self.handle
            .address()
            .get()
            .execute()
            .try_filter(|m| futures_util::future::ready(m.header.family == AddressFamily::Inet6))
            .take(MAX_DUMP)
            .try_collect()
            .await
            .map_err(|e| format!("listing addresses: {}", readable(&e)))
    }

    async fn routes_v6(&self) -> Result<Vec<RouteMessage>, String> {
        self.handle
            .route()
            .get(RouteMessageBuilder::<Ipv6Addr>::new().table_id(0).build())
            .execute()
            .take(MAX_DUMP)
            .try_collect()
            .await
            .map_err(|e| format!("listing routes: {}", readable(&e)))
    }

    #[allow(clippy::type_complexity)]
    async fn held(
        &self,
        names: &std::collections::BTreeMap<u32, IfName>,
    ) -> Result<
        (
            std::collections::BTreeSet<(IfName, IpNet)>,
            std::collections::BTreeSet<KernelRoute>,
        ),
        String,
    > {
        let addresses: Vec<AddressMessage> = self
            .handle
            .address()
            .get()
            .execute()
            .take(MAX_DUMP)
            .try_collect()
            .await
            .map_err(|e| format!("listing addresses: {}", readable(&e)))?;
        let addresses = addresses
            .iter()
            .filter_map(|m| Some((names.get(&m.header.index)?.clone(), configured_address(m)?)))
            .collect();
        let mut routes = std::collections::BTreeSet::new();
        let v4: Vec<RouteMessage> = self
            .handle
            .route()
            .get(
                RouteMessageBuilder::<std::net::Ipv4Addr>::new()
                    .table_id(0)
                    .build(),
            )
            .execute()
            .take(MAX_DUMP)
            .try_collect()
            .await
            .map_err(|e| format!("listing routes: {}", readable(&e)))?;
        for m in v4.iter().chain(self.routes_v6().await?.iter()) {
            routes.extend(static_routes(m, names));
        }
        Ok((addresses, routes))
    }

    async fn learned(
        &self,
        names: &std::collections::BTreeMap<u32, IfName>,
    ) -> Result<Vec<Learned>, String> {
        let mut out = Vec::new();
        for m in self.addresses_v6().await? {
            let Some(interface) = names.get(&m.header.index) else {
                continue;
            };
            if let Some((address, valid_secs, preferred_secs)) = self_made(&m) {
                out.push(Learned::Address {
                    interface: interface.clone(),
                    address,
                    valid_secs,
                    preferred_secs,
                });
            }
        }
        for m in self.routes_v6().await? {
            let Some((dst, gateway, oif, metric, table, expires_secs)) = ra_route(&m) else {
                continue;
            };
            let Some(interface) = names.get(&oif) else {
                continue;
            };
            out.push(Learned::Route {
                interface: interface.clone(),
                dst,
                gateway,
                metric,
                table,
                expires_secs,
            });
        }
        Ok(out)
    }

    async fn flush_learned(
        &self,
        links: &[IfName],
        keep: &[(IfName, IpNet)],
    ) -> Result<usize, String> {
        let mut index = std::collections::BTreeMap::new();
        for l in links {
            if let Some(link) = self.find(l).await? {
                index.insert(link.index, l.clone());
            }
        }
        let mut gone = 0usize;
        for m in self.addresses_v6().await? {
            let Some(name) = index.get(&m.header.index) else {
                continue;
            };
            let Some((net, _, _)) = self_made(&m) else {
                continue;
            };
            if keep.iter().any(|(i, a)| i == name && *a == IpNet::V6(net)) {
                continue;
            }
            match self.handle.address().del(m).execute().await {
                Ok(()) => gone = gone.saturating_add(1),
                Err(e) if matches!(errno(&e), Some(EADDRNOTAVAIL | ENOENT)) => {}
                Err(e) => return Err(format!("removing {net} from '{name}': {}", readable(&e))),
            }
        }
        for m in self.routes_v6().await? {
            let Some((dst, ..)) = ra_route(&m) else {
                continue;
            };
            let oif = m.attributes.iter().find_map(|a| match a {
                RouteAttribute::Oif(i) => Some(*i),
                _ => None,
            });
            let Some(name) = oif.and_then(|i| index.get(&i)) else {
                continue;
            };
            match self.handle.route().del(m).execute().await {
                Ok(()) => gone = gone.saturating_add(1),
                Err(e) if matches!(errno(&e), Some(ESRCH | ENOENT)) => {}
                Err(e) => {
                    return Err(format!(
                        "removing RA route {dst} on '{name}': {}",
                        readable(&e)
                    ));
                }
            }
        }
        Ok(gone)
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

/// One path of a multipath route.
fn next_hop(r: &KernelRoute, oif: u32) -> RouteNextHop {
    let mut nh = RouteNextHop::default();
    nh.interface_index = oif;
    if let Some(g) = r.gateway {
        nh.attributes.push(RouteAttribute::Gateway(match g {
            IpAddr::V4(v4) => RouteAddress::Inet(v4),
            IpAddr::V6(v6) => RouteAddress::Inet6(v6),
        }));
    }
    nh
}

/// The multipath route of `paths` (one table, prefix and metric).
fn multipath_msg(paths: &[KernelRoute], hops: Vec<RouteNextHop>) -> Result<RouteMessage, String> {
    let first = paths.first().ok_or("no paths")?;
    Ok(RouteMessageBuilder::<IpAddr>::new()
        .destination_prefix(first.dst.addr(), first.dst.prefix_len())
        .map_err(|e| e.to_string())?
        .priority(first.metric)
        .table_id(first.table)
        .protocol(RouteProtocol::Static)
        .multipath(hops)
        .build())
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

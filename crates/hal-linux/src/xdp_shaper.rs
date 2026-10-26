//! Queues (G4.9b) and kernel delivery to PPPoE subscribers (G4.3ca): the
//! tc programs of the XDP object (`shape_egress`, `shape_ingress`,
//! `bng_egress`), their maps, `fq` on the shaped ports, and `bng0` with one
//! route per subscriber.
//!
//! - **Shaper.** `shape_egress` gives each packet to a target its departure
//!   time (`skb->tstamp`, EDT) and `fq` holds it until then; `fq` goes on
//!   every transmit queue of the port (`mq` + one `fq` per queue, or a root
//!   `fq` on a single-queue port), with a per-flow limit large enough for a
//!   shaped target's queue (the shaper drops by its own limits first).
//!   `shape_ingress` polices the queues' upload. Taking the plan away
//!   detaches the programs and gives the ports their default qdisc back.
//! - **`bng0`** (the dummy the slow path already used): each PPPoE
//!   subscriber gets a route to its IPv4 /32, /64 and delegated prefix
//!   through it with the session's MTU (so the kernel answers "fragmentation
//!   needed"/"packet too big", RFC 1191/8201, and decrements the TTL), and
//!   `bng_egress` encapsulates what the kernel sends there and redirects it
//!   to the access port. That is how the slow path (TTL, MTU, firewall,
//!   ICMP) and a shaped download reach the subscriber with XDP on.
//! - Routes and qdiscs are kernel state that survives a reload of the
//!   object; the tc links and the maps do not, and come back after one.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use aya::Ebpf;
use aya::maps::{Array, HashMap, PerCpuArray};
use aya::programs::SchedClassifier;
use aya::programs::tc::{SchedClassifierLinkId, TcAttachType};
use corerouter_dataplane_ebpf_common::maps as m;
use corerouter_dataplane_ebpf_common::policer::Rate;
use corerouter_dataplane_ebpf_common::queue::{self as q, Conf, Dir, Pcq};
use corerouter_dataplane_ebpf_common::shaper::{self, KIND_CODEL, KIND_FIFO, Queue};
use corerouter_hal::HalError;
use corerouter_hal::queue::{DirSpec, Kind, QueueCounters, ShaperPlan, ShaperStatus};
use corerouter_model::IfName;
use ipnet::IpNet;

use super::{Loaded, monotonic_ns, rejected};

/// `fq` limits on a shaped port: packets in all (default 10 000) and per
/// flow (default 100: a 1 Gbit/s target with 100 ms queued is ~8 300
/// packets of one flow). The shaper drops by its own per-target limits
/// first; these only keep `fq` from dropping before it.
const FQ_PLIMIT: u32 = 200_000;
const FQ_FLOW_PLIMIT: u32 = 20_000;
/// `linux/pkt_sched.h`.
const TCA_FQ_PLIMIT: u16 = 1;
const TCA_FQ_FLOW_PLIMIT: u16 = 2;

/// Which program on which hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Hook {
    Egress,
    Ingress,
    Bng,
}

/// The tc links of a loaded object (gone with it).
#[derive(Default)]
pub(super) struct TcLinks {
    links: BTreeMap<(IfName, Hook), SchedClassifierLinkId>,
    loaded: bool,
}

/// What the loader keeps of the shaper between reloads.
#[derive(Default)]
pub(super) struct ShaperState {
    pub plan: ShaperPlan,
    /// The plan the maps hold now (empty after a reload).
    applied: ShaperPlan,
    /// Ports whose root qdisc we replaced (kernel state).
    fq: BTreeSet<IfName>,
    /// `bng0`'s index while PPPoE delivery is on.
    bng: Option<u32>,
    /// Routes through `bng0` per session index (kernel state).
    routes: BTreeMap<u32, Vec<(IpNet, u16)>>,
    /// The download queue words of each shaped session.
    pub shapes: BTreeMap<u32, [u64; shaper::QUEUE_WORDS]>,
    /// Bytes per queue at the last status, for the rates.
    last: BTreeMap<String, (u64, [u64; 2])>,
    /// PCQ sub-streams per queue slot, counted at most every 10 s (one
    /// syscall per entry).
    pcq: (u64, BTreeMap<u32, u32>),
    nl: Option<Netlink>,
    error: Option<String>,
}

impl std::fmt::Debug for ShaperState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShaperState")
            .field("queues", &self.plan.queues.len())
            .field("fq", &self.fq)
            .field("bng", &self.bng)
            .field("routes", &self.routes.len())
            .finish()
    }
}

impl ShaperState {
    /// The object must be loaded for the shaper alone.
    pub fn wanted(&self) -> bool {
        !self.plan.is_empty()
    }

    /// Nothing of the shaper is left in the kernel (no `fq` of ours).
    pub fn idle(&self) -> bool {
        self.fq.is_empty()
    }

    pub fn queues(&self) -> bool {
        !self.plan.queues.is_empty()
    }

    pub fn pcq(&self) -> bool {
        self.plan
            .queues
            .iter()
            .any(|x| x.upload.pcq.is_some() || x.download.pcq.is_some())
    }

    /// The `SETTINGS` word of the shaper.
    pub fn word(&self, sessions_on: bool) -> u64 {
        let mut w = 0;
        if self.queues() {
            w |= q::ON_QUEUES;
        }
        if sessions_on && !self.shapes.is_empty() {
            w |= q::ON_SESSIONS;
        }
        w
    }
}

/// A private netlink connection for qdiscs and routes (one runtime, kept).
struct Netlink {
    rt: tokio::runtime::Runtime,
    handle: rtnetlink::Handle,
}

impl Netlink {
    fn open() -> Result<Self, HalError> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .map_err(|e| HalError::Rejected(format!("shaper: runtime: {e}")))?;
        let handle = rt
            .block_on(async {
                let (conn, handle, _) = rtnetlink::new_connection()?;
                tokio::spawn(conn);
                Ok::<_, std::io::Error>(handle)
            })
            .map_err(|e| HalError::Rejected(format!("shaper: netlink: {e}")))?;
        Ok(Netlink { rt, handle })
    }

    /// Send one qdisc message; `Ok` on the kernel's ACK.
    fn qdisc(
        &self,
        msg: rtnetlink::packet_route::tc::TcMessage,
        flags: u16,
        new: bool,
    ) -> Result<(), String> {
        use futures_util::StreamExt;
        use rtnetlink::packet_core::{NLM_F_ACK, NLM_F_REQUEST, NetlinkMessage, NetlinkPayload};
        use rtnetlink::packet_route::RouteNetlinkMessage;
        let mut handle = self.handle.clone();
        self.rt.block_on(async move {
            let body = if new {
                RouteNetlinkMessage::NewQueueDiscipline(msg)
            } else {
                RouteNetlinkMessage::DelQueueDiscipline(msg)
            };
            let mut req = NetlinkMessage::from(body);
            req.header.flags = NLM_F_REQUEST | NLM_F_ACK | flags;
            let mut resp = handle.request(req).map_err(|e| e.to_string())?;
            while let Some(m) = resp.next().await {
                if let NetlinkPayload::Error(e) = m.payload
                    && e.code.is_some()
                {
                    return Err(e.to_string());
                }
            }
            Ok(())
        })
    }

    /// Add (or replace) or remove a route through `bng0`.
    fn route(&self, ifindex: u32, net: IpNet, mtu: u16, add: bool) -> Result<(), String> {
        use rtnetlink::RouteMessageBuilder;
        use rtnetlink::packet_route::route::{RouteAttribute, RouteMetric};
        let mut msg = match net {
            IpNet::V4(n) => RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(n.network(), n.prefix_len())
                .output_interface(ifindex)
                .build(),
            IpNet::V6(n) => RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(n.network(), n.prefix_len())
                .output_interface(ifindex)
                .build(),
        };
        if add && mtu != 0 {
            msg.attributes
                .push(RouteAttribute::Metrics(vec![RouteMetric::Mtu(u32::from(
                    mtu,
                ))]));
        }
        let h = self.handle.clone();
        self.rt.block_on(async move {
            let out = if add {
                h.route().add(msg).replace().execute().await
            } else {
                h.route().del(msg).execute().await
            };
            match out {
                Ok(()) => Ok(()),
                // Removing a route already gone is fine.
                Err(rtnetlink::Error::NetlinkError(e)) if !add && e.raw_code() == -3 => Ok(()),
                Err(e) => Err(format!("route {net} via bng0: {e}")),
            }
        })
    }
}

/// Transmit queues of `name` (sysfs), at least 1.
fn tx_queues(name: &IfName) -> u16 {
    std::fs::read_dir(format!("/sys/class/net/{name}/queues"))
        .map(|d| {
            d.filter_map(Result::ok)
                .filter(|e| e.file_name().to_string_lossy().starts_with("tx-"))
                .count()
        })
        .ok()
        .and_then(|n| u16::try_from(n).ok())
        .unwrap_or(1)
        .max(1)
}

fn fq_message(
    ifindex: u32,
    parent: rtnetlink::packet_route::tc::TcHandle,
) -> rtnetlink::packet_route::tc::TcMessage {
    use rtnetlink::packet_core::DefaultNla;
    use rtnetlink::packet_route::tc::{TcAttribute, TcMessage, TcOption};
    let mut msg = TcMessage::with_index(i32::try_from(ifindex).unwrap_or(0));
    msg.header.parent = parent;
    msg.attributes.push(TcAttribute::Kind("fq".into()));
    msg.attributes.push(TcAttribute::Options(vec![
        TcOption::Other(DefaultNla::new(
            TCA_FQ_PLIMIT,
            FQ_PLIMIT.to_ne_bytes().to_vec(),
        )),
        TcOption::Other(DefaultNla::new(
            TCA_FQ_FLOW_PLIMIT,
            FQ_FLOW_PLIMIT.to_ne_bytes().to_vec(),
        )),
    ]));
    msg
}

/// `fq` on every transmit queue of `name`: `mq` (handle 1:) with one `fq`
/// per queue, or a root `fq`.
fn ensure_fq(nl: &Netlink, name: &IfName, ifindex: u32) -> Result<(), String> {
    use rtnetlink::packet_core::{NLM_F_CREATE, NLM_F_REPLACE};
    use rtnetlink::packet_route::tc::{TcAttribute, TcHandle, TcMessage};
    let n = tx_queues(name);
    let flags = NLM_F_CREATE | NLM_F_REPLACE;
    if n <= 1 {
        return nl.qdisc(fq_message(ifindex, TcHandle::ROOT), flags, true);
    }
    let mut mq = TcMessage::with_index(i32::try_from(ifindex).unwrap_or(0));
    mq.header.parent = TcHandle::ROOT;
    mq.header.handle = TcHandle { major: 1, minor: 0 };
    mq.attributes.push(TcAttribute::Kind("mq".into()));
    nl.qdisc(mq, flags, true)?;
    for i in 1..=n {
        nl.qdisc(
            fq_message(ifindex, TcHandle { major: 1, minor: i }),
            flags,
            true,
        )?;
    }
    Ok(())
}

/// The port's default qdisc back (deleting ours).
fn drop_fq(nl: &Netlink, ifindex: u32) {
    use rtnetlink::packet_route::tc::{TcHandle, TcMessage};
    let mut msg = TcMessage::with_index(i32::try_from(ifindex).unwrap_or(0));
    msg.header.parent = TcHandle::ROOT;
    let _ = nl.qdisc(msg, 0, false);
}

// --- Map values -------------------------------------------------------------

fn rate_of(d: &DirSpec) -> Rate {
    Rate::routeros(
        d.rate_bps,
        d.burst_bps,
        d.threshold_bps,
        u64::from(d.burst_time_ms) * 1_000_000,
        u64::from(d.bucket_milli),
    )
}

/// What `kind` does at `rate` bytes per second.
pub(super) fn queue_of(kind: &Kind, rate: u64) -> Queue {
    match *kind {
        Kind::Fifo { limit_bytes } => Queue {
            kind: KIND_FIFO,
            ecn: false,
            limit_ns: shaper::fifo_limit_ns(limit_bytes, rate),
            target_ns: 0,
            interval_ns: 0,
        },
        Kind::Codel {
            target_us,
            interval_us,
            ecn,
            limit_packets,
        } => Queue {
            kind: KIND_CODEL,
            ecn,
            limit_ns: shaper::fifo_limit_ns(u64::from(limit_packets) * 1514, rate),
            target_ns: u64::from(target_us) * 1000,
            interval_ns: u64::from(interval_us).max(1) * 1000,
        },
    }
}

fn dir_of(d: &DirSpec) -> Dir {
    let rate = rate_of(d);
    Dir {
        rate,
        queue: queue_of(&d.kind, rate.rate),
        // PCQ with no rate of its own only splits the queue's limit
        // equally in RouterOS; here the queue's clock does it (no
        // per-address split).
        pcq: d
            .pcq
            .filter(|p| p.rate_bps > 0)
            .map_or(Pcq::default(), |p| {
                let r = Rate::routeros(p.rate_bps, 0, 0, 0, u64::from(d.bucket_milli));
                Pcq {
                    on: true,
                    rate: Rate {
                        rate: r.rate,
                        depth: r.depth,
                        ..Rate::default()
                    },
                    queue: queue_of(&p.kind, r.rate),
                    by_src: p.by_src,
                    mask4: p.mask4,
                    mask6: p.mask6,
                }
            }),
    }
}

pub(super) fn conf_of(spec: &corerouter_hal::queue::QueueSpec) -> Conf {
    Conf {
        up: dir_of(&spec.upload),
        down: dir_of(&spec.download),
    }
}

fn map<'a>(ebpf: &'a mut Ebpf, name: &str) -> Result<&'a mut aya::maps::Map, HalError> {
    ebpf.map_mut(name)
        .ok_or_else(|| HalError::Rejected(format!("shaper: no {name} map")))
}

fn err(what: &'static str) -> impl Fn(aya::maps::MapError) -> HalError {
    move |e| rejected(what, &e)
}

/// Write queue `slot` (config, fresh states, counters at zero).
fn put_queue(ebpf: &mut Ebpf, slot: u32, c: &Conf, fresh_counts: bool) -> Result<(), HalError> {
    let now = monotonic_ns();
    let mut conf =
        Array::<_, q::ConfWords>::try_from(map(ebpf, m::Q_CONF)?).map_err(err("Q_CONF map"))?;
    conf.set(slot, c.to_words(), 0).map_err(err("Q_CONF set"))?;
    let mut st =
        Array::<_, shaper::State>::try_from(map(ebpf, m::Q_STATE)?).map_err(err("Q_STATE map"))?;
    st.set(slot * 2, shaper::fresh(&c.up.rate, now), 0)
        .map_err(err("Q_STATE set"))?;
    st.set(slot * 2 + 1, shaper::fresh(&c.down.rate, now), 0)
        .map_err(err("Q_STATE set"))?;
    if fresh_counts {
        let mut cnt =
            Array::<_, q::Counts>::try_from(map(ebpf, m::Q_COUNT)?).map_err(err("Q_COUNT map"))?;
        cnt.set(slot * 2, [0; q::COUNT_WORDS], 0)
            .map_err(err("Q_COUNT set"))?;
        cnt.set(slot * 2 + 1, [0; q::COUNT_WORDS], 0)
            .map_err(err("Q_COUNT set"))?;
    }
    Ok(())
}

fn clear_queue(ebpf: &mut Ebpf, slot: u32) -> Result<(), HalError> {
    let mut conf =
        Array::<_, q::ConfWords>::try_from(map(ebpf, m::Q_CONF)?).map_err(err("Q_CONF map"))?;
    conf.set(slot, [0; q::CONF_WORDS], 0)
        .map_err(err("Q_CONF clear"))
}

/// Make the queue maps go from `from` to `to`. Order: a queue's config
/// before the targets that point at it; stale targets before their queue
/// is cleared.
fn sync_maps(ebpf: &mut Ebpf, from: &ShaperPlan, to: &ShaperPlan) -> Result<(), HalError> {
    if to.queues.len() > q::Q_MAX as usize {
        return Err(HalError::Rejected(format!(
            "shaper: at most {} queues",
            q::Q_MAX
        )));
    }
    for (i, spec) in to.queues.iter().enumerate() {
        let old = from.queues.get(i);
        if old == Some(spec) {
            continue;
        }
        let slot = u32::try_from(i).unwrap_or(u32::MAX);
        // Same key, new limits: a rate change (CoA, edit) keeps counters.
        let fresh = old.is_none_or(|o| o.key != spec.key);
        put_queue(ebpf, slot, &conf_of(spec), fresh)?;
    }
    super::sync_trie(ebpf, m::Q_V4, m::Q_V6, &from.prefixes, &to.prefixes)?;
    let mut ifaces =
        HashMap::<_, u32, u32>::try_from(map(ebpf, m::Q_IFACE)?).map_err(err("Q_IFACE map"))?;
    let old: Vec<u32> = ifaces.keys().filter_map(Result::ok).collect();
    let mut want = BTreeMap::new();
    for (name, slot) in &to.interfaces {
        if let Ok(i) = super::ifindex(name) {
            want.insert(i, *slot);
        }
    }
    for k in old.iter().filter(|k| !want.contains_key(k)) {
        let _ = ifaces.remove(k);
    }
    for (k, v) in &want {
        ifaces.insert(*k, *v, 0).map_err(err("Q_IFACE insert"))?;
    }
    for i in to.queues.len()..from.queues.len() {
        clear_queue(ebpf, u32::try_from(i).unwrap_or(u32::MAX))?;
    }
    Ok(())
}

/// Load the three tc programs once per object.
fn load_programs(l: &mut Loaded) -> Result<(), HalError> {
    if l.tc.loaded {
        return Ok(());
    }
    for name in [m::SHAPE_EGRESS, m::SHAPE_INGRESS, m::BNG_EGRESS] {
        let p: &mut SchedClassifier = l
            .ebpf
            .program_mut(name)
            .ok_or_else(|| HalError::Rejected(format!("shaper: no program {name} in the object")))?
            .try_into()
            .map_err(|e| rejected("program type", &e))?;
        p.load()
            .map_err(|e| rejected(&format!("the kernel refused {name}"), &e))?;
    }
    l.tc.loaded = true;
    Ok(())
}

fn program_of(hook: Hook) -> (&'static str, TcAttachType) {
    match hook {
        Hook::Egress => (m::SHAPE_EGRESS, TcAttachType::Egress),
        Hook::Ingress => (m::SHAPE_INGRESS, TcAttachType::Ingress),
        Hook::Bng => (m::BNG_EGRESS, TcAttachType::Egress),
    }
}

/// Attach to `want`, detach from the rest.
fn attach(l: &mut Loaded, want: &BTreeSet<(IfName, Hook)>) -> Result<(), HalError> {
    let stale: Vec<(IfName, Hook)> =
        l.tc.links
            .keys()
            .filter(|k| !want.contains(*k))
            .cloned()
            .collect();
    for k in stale {
        if let Some(id) = l.tc.links.remove(&k) {
            let (name, _) = program_of(k.1);
            if let Some(p) = l.ebpf.program_mut(name)
                && let Ok(p) = <&mut SchedClassifier>::try_from(p)
                && let Err(e) = p.detach(id)
            {
                log::warn!("shaper: detaching {name} from {}: {e}", k.0);
            }
        }
    }
    if want.is_empty() {
        return Ok(());
    }
    load_programs(l)?;
    for k in want {
        if l.tc.links.contains_key(k) {
            continue;
        }
        let (name, at) = program_of(k.1);
        let p: &mut SchedClassifier = l
            .ebpf
            .program_mut(name)
            .ok_or_else(|| HalError::Rejected(format!("shaper: program {name} gone")))?
            .try_into()
            .map_err(|e| rejected("program type", &e))?;
        let id = p
            .attach(k.0.as_str(), at)
            .map_err(|e| rejected(&format!("attaching {name} to {}", k.0), &e))?;
        l.tc.links.insert(k.clone(), id);
    }
    Ok(())
}

impl ShaperState {
    fn netlink(&mut self) -> Result<&Netlink, HalError> {
        if self.nl.is_none() {
            self.nl = Some(Netlink::open()?);
        }
        self.nl
            .as_ref()
            .ok_or_else(|| HalError::Rejected("shaper: netlink".into()))
    }

    /// Bring the loaded object (or none) to `self.plan` and the session
    /// switches: maps, `fq`, links, `bng0`. `pppoe`: the PPPoE data plane
    /// is on (bng0 and the session routes).
    pub(super) fn reach(
        &mut self,
        loaded: Option<&mut Loaded>,
        pppoe: bool,
        sessions_on: bool,
    ) -> Result<(), HalError> {
        let plan = self.plan.clone();
        // bng0 first (its program goes on below).
        if pppoe && self.bng.is_none() {
            let idx = crate::pppoe_io::ensure_dummy(crate::pppoe_io::SLOW_DEVICE)
                .map_err(|e| HalError::Rejected(format!("shaper: {e}")))?;
            self.bng = Some(idx);
        }
        let mut want: BTreeSet<(IfName, Hook)> = BTreeSet::new();
        for p in &plan.ports {
            want.insert((p.clone(), Hook::Egress));
            want.insert((p.clone(), Hook::Ingress));
        }
        if plan.sessions {
            for p in &plan.access_ports {
                want.insert((p.clone(), Hook::Egress));
            }
        }
        if pppoe && let Ok(bng) = crate::pppoe_io::SLOW_DEVICE.parse::<IfName>() {
            want.insert((bng, Hook::Bng));
        }
        // fq where something is shaped on the way out.
        let fq_want: BTreeSet<IfName> = want
            .iter()
            .filter(|(_, h)| *h == Hook::Egress)
            .map(|(n, _)| n.clone())
            .collect();
        let gone: Vec<IfName> = self.fq.difference(&fq_want).cloned().collect();
        let new: Vec<IfName> = fq_want.difference(&self.fq).cloned().collect();
        if !gone.is_empty() || !new.is_empty() {
            let nl = self.netlink()?;
            for name in &gone {
                if let Ok(i) = super::ifindex(name) {
                    drop_fq(nl, i);
                }
            }
            let mut put = Vec::new();
            for name in &new {
                let i = super::ifindex(name)?;
                ensure_fq(nl, name, i)
                    .map_err(|e| HalError::Rejected(format!("shaper: fq on {name}: {e}")))?;
                put.push(name.clone());
            }
            for n in gone {
                self.fq.remove(&n);
            }
            self.fq.extend(put);
        }
        let Some(l) = loaded else {
            self.applied = ShaperPlan::default();
            return Ok(());
        };
        if l.queues {
            let applied = std::mem::take(&mut self.applied);
            sync_maps(&mut l.ebpf, &applied, &plan)?;
            self.applied = plan;
        }
        write_word(&mut l.ebpf, self.word(sessions_on))?;
        attach(l, &want)
    }

    /// The object was reloaded: maps are empty, links gone.
    pub(super) fn reloaded(&mut self) {
        self.applied = ShaperPlan::default();
    }

    /// Session `idx`'s download queue (`None`: policed in XDP) and its
    /// routes through `bng0` (PPPoE only), after its session words went in.
    pub(super) fn session(
        &mut self,
        ebpf: Option<&mut Ebpf>,
        idx: u32,
        s: &corerouter_dataplane_ebpf_common::pppoe::Session,
        shape: Option<[u64; shaper::QUEUE_WORDS]>,
        routes: Vec<(IpNet, u16)>,
    ) -> Result<(), HalError> {
        match shape {
            Some(w) => {
                self.shapes.insert(idx, w);
            }
            None => {
                self.shapes.remove(&idx);
            }
        }
        if let (Some(ebpf), Some(w)) = (ebpf, shape) {
            put_session(ebpf, idx, &s.down, w)?;
        }
        self.set_routes(idx, routes)
    }

    fn set_routes(&mut self, idx: u32, routes: Vec<(IpNet, u16)>) -> Result<(), HalError> {
        let Some(bng) = self.bng else {
            return Ok(());
        };
        let old = self.routes.get(&idx).cloned().unwrap_or_default();
        if old == routes {
            return Ok(());
        }
        let nl = self.netlink()?;
        let mut first = None;
        for (n, _) in old.iter().filter(|r| !routes.iter().any(|x| x.0 == r.0)) {
            if let Err(e) = nl.route(bng, *n, 0, false) {
                first.get_or_insert(e);
            }
        }
        for (n, mtu) in routes.iter().filter(|r| !old.contains(r)) {
            if let Err(e) = nl.route(bng, *n, *mtu, true) {
                first.get_or_insert(e);
            }
        }
        if routes.is_empty() {
            self.routes.remove(&idx);
        } else {
            self.routes.insert(idx, routes);
        }
        match first {
            Some(e) => Err(HalError::Rejected(format!("bng0: {e}"))),
            None => Ok(()),
        }
    }

    pub(super) fn session_gone(&mut self, idx: u32) -> Result<(), HalError> {
        self.shapes.remove(&idx);
        self.set_routes(idx, Vec::new())
    }

    /// Counters by queue key, the backlog, the rates since the last call.
    pub(super) fn status(&mut self, loaded: Option<&mut Loaded>) -> ShaperStatus {
        let Some(l) = loaded else {
            return ShaperStatus {
                unavailable: self.error.clone().or_else(|| {
                    (!self.plan.is_empty()).then(|| "the eBPF object is not loaded".to_owned())
                }),
                ..ShaperStatus::default()
            };
        };
        let mut out = ShaperStatus {
            ports: l
                .tc
                .links
                .keys()
                .map(|(n, _)| n.clone())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            ..ShaperStatus::default()
        };
        if let Some(mp) = l.ebpf.map_mut(m::SHAPE_STATS)
            && let Ok(arr) = PerCpuArray::<_, u64>::try_from(mp)
        {
            out.stats = q::Stat::ALL
                .iter()
                .filter_map(|s| {
                    let total: u64 = arr.get(&(*s as u32), 0).ok()?.iter().sum();
                    (total > 0).then_some((s.name(), total))
                })
                .collect();
        }
        if !l.queues {
            return out;
        }
        let now = monotonic_ns();
        if l.pcq && now.saturating_sub(self.pcq.0) > 10_000_000_000 {
            self.pcq = (now, pcq_counts(&mut l.ebpf));
        }
        let counts: Vec<Option<q::Counts>> = match l
            .ebpf
            .map_mut(m::Q_COUNT)
            .map(Array::<_, q::Counts>::try_from)
        {
            Some(Ok(a)) => (0..self.plan.queues.len() * 2)
                .map(|i| a.get(&u32::try_from(i).unwrap_or(u32::MAX), 0).ok())
                .collect(),
            _ => Vec::new(),
        };
        let backlog: Vec<u64> = match l
            .ebpf
            .map_mut(m::Q_STATE)
            .map(Array::<_, shaper::State>::try_from)
        {
            Some(Ok(a)) => (0..self.plan.queues.len() * 2)
                .map(|i| {
                    a.get(&u32::try_from(i).unwrap_or(u32::MAX), 0)
                        .map(|st| shaper::backlog_ns(&st, now))
                        .unwrap_or(0)
                })
                .collect(),
            _ => Vec::new(),
        };
        for (i, spec) in self.plan.queues.iter().enumerate() {
            let mut c = QueueCounters {
                pcq_queues: self
                    .pcq
                    .1
                    .get(&u32::try_from(i).unwrap_or(u32::MAX))
                    .copied()
                    .unwrap_or(0),
                ..QueueCounters::default()
            };
            for dir in 0..2 {
                let Some(Some(w)) = counts.get(i * 2 + dir) else {
                    continue;
                };
                let [packets, bytes, dropped, _marked] = *w;
                if let (Some(p), Some(b), Some(d)) = (
                    c.packets.get_mut(dir),
                    c.bytes.get_mut(dir),
                    c.dropped.get_mut(dir),
                ) {
                    *p = packets;
                    *b = bytes;
                    *d = dropped;
                }
                if dir == 1
                    && let (Some(slot), Some(ns)) = (c.queued_us.get_mut(1), backlog.get(i * 2 + 1))
                {
                    *slot = ns / 1000;
                }
            }
            if let Some((at, prev)) = self.last.get(&spec.key) {
                let dt = now.saturating_sub(*at).max(1);
                for dir in 0..2 {
                    if let (Some(r), Some(b), Some(p)) =
                        (c.rate_bps.get_mut(dir), c.bytes.get(dir), prev.get(dir))
                    {
                        *r = b
                            .saturating_sub(*p)
                            .saturating_mul(8)
                            .saturating_mul(1_000_000_000)
                            / dt;
                    }
                }
            }
            self.last.insert(spec.key.clone(), (now, c.bytes));
            out.queues.push((spec.key.clone(), c));
        }
        self.last
            .retain(|k, _| self.plan.queues.iter().any(|q| &q.key == k));
        out
    }
}

/// Session `idx`'s download queue words and a fresh clock.
fn put_session(
    ebpf: &mut Ebpf,
    idx: u32,
    down: &Rate,
    w: [u64; shaper::QUEUE_WORDS],
) -> Result<(), HalError> {
    let mut shape = Array::<_, [u64; shaper::QUEUE_WORDS]>::try_from(map(ebpf, m::SUB_SHAPE)?)
        .map_err(err("SUB_SHAPE map"))?;
    shape.set(idx, w, 0).map_err(err("SUB_SHAPE set"))?;
    let mut st =
        Array::<_, shaper::State>::try_from(map(ebpf, m::SUB_EDT)?).map_err(err("SUB_EDT map"))?;
    st.set(idx, shaper::fresh(down, monotonic_ns()), 0)
        .map_err(err("SUB_EDT set"))
}

/// After a reload: every shaped session's queue back.
pub(super) fn refill_sessions(
    ebpf: &mut Ebpf,
    st: &ShaperState,
    sessions: &BTreeMap<u32, corerouter_dataplane_ebpf_common::pppoe::Session>,
) -> Result<(), HalError> {
    for (idx, w) in &st.shapes {
        if let Some(s) = sessions.get(idx) {
            put_session(ebpf, *idx, &s.down, *w)?;
        }
    }
    Ok(())
}

fn write_word(ebpf: &mut Ebpf, w: u64) -> Result<(), HalError> {
    let mut arr =
        Array::<_, u64>::try_from(map(ebpf, m::SETTINGS)?).map_err(err("SETTINGS map"))?;
    arr.set(q::SETTINGS_SLOT, w, 0).map_err(err("SETTINGS set"))
}

/// The routes a PPPoE session needs through `bng0`: its /32, /64 and
/// delegated prefix, with its MTU.
pub(super) fn routes_of(p: &corerouter_hal::pppoe::PppoeSession) -> Vec<(IpNet, u16)> {
    if p.ipoe {
        return Vec::new();
    }
    let mtu = if p.mtu == 0 { 1492 } else { p.mtu };
    let mut v = Vec::new();
    if let Some(ip) = p.ipv4 {
        v.push((IpNet::from(IpAddr::V4(ip)), mtu));
    }
    let v6 = |b: [u8; 8], len: u8| {
        let mut a = [0u8; 16];
        for (d, s) in a.iter_mut().zip(b) {
            *d = s;
        }
        IpNet::new(IpAddr::V6(Ipv6Addr::from(a)), len).ok()
    };
    if let Some(n) = p.ipv6_prefix.and_then(|b| v6(b, 64)) {
        v.push((n, mtu));
    }
    if let Some(n) = p.delegated.and_then(|(b, len)| v6(b, len)) {
        v.push((n, mtu));
    }
    v
}

/// LRU entries of the PCQ map, per queue slot (for the status, rarely:
/// one syscall per entry).
fn pcq_counts(ebpf: &mut Ebpf) -> BTreeMap<u32, u32> {
    let mut out = BTreeMap::new();
    let Some(mp) = ebpf.map_mut(m::Q_PCQ) else {
        return out;
    };
    let Ok(h) = HashMap::<_, [u8; q::PCQ_KEY_LEN], shaper::SubState>::try_from(mp) else {
        return out;
    };
    for k in h.keys().filter_map(Result::ok) {
        let [a, b, c, d, ..] = k;
        *out.entry(u32::from_le_bytes([a, b, c, d])).or_insert(0) += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs_become_map_values() {
        let d = DirSpec {
            rate_bps: 10_000_000,
            burst_bps: 20_000_000,
            threshold_bps: 15_000_000,
            burst_time_ms: 8000,
            bucket_milli: 100,
            kind: Kind::default(),
            pcq: Some(corerouter_hal::queue::PcqSpec {
                rate_bps: 2_000_000,
                by_src: false,
                mask4: 32,
                mask6: 64,
                kind: Kind::Fifo {
                    limit_bytes: 51_200,
                },
            }),
        };
        let dir = dir_of(&d);
        assert_eq!(dir.rate.rate, 1_250_000);
        assert_eq!(dir.rate.depth, 125_000, "bucket-size 0.1");
        assert!(dir.rate.bursts());
        assert_eq!(dir.queue.kind, KIND_CODEL);
        assert_eq!(
            (dir.queue.target_ns, dir.queue.interval_ns),
            (5_000_000, 100_000_000)
        );
        let p = dir.pcq;
        assert!(p.on);
        assert_eq!(
            (p.rate.rate, p.mask6, p.queue.kind),
            (250_000, 64, KIND_FIFO)
        );
        // 50 KiB at 2 Mbit/s ≈ 205 ms of queue.
        assert!(
            (200_000_000..=210_000_000).contains(&p.queue.limit_ns),
            "{}",
            p.queue.limit_ns
        );
        let spec = corerouter_hal::queue::QueueSpec {
            key: "*1".into(),
            upload: d,
            download: d,
        };
        let back = Conf::from_words(&conf_of(&spec).to_words());
        assert_eq!(back.down.rate, dir.rate);
    }

    /// The object has the shaper's maps and three tc programs, and no
    /// panic path (a division LLVM cannot prove safe links Rust's panic
    /// and the verifier refuses the program: "last insn is not an exit").
    #[test]
    fn the_object_has_the_shaper() {
        let obj = aya_obj::Object::parse(super::super::OBJECT).unwrap();
        for name in [
            m::SUB_SHAPE,
            m::SUB_EDT,
            m::Q_V4,
            m::Q_V6,
            m::Q_IFACE,
            m::Q_CONF,
            m::Q_STATE,
            m::Q_COUNT,
            m::Q_PCQ,
            m::SHAPE_STATS,
        ] {
            assert!(obj.maps.contains_key(name), "map {name}");
        }
        for p in [m::SHAPE_EGRESS, m::SHAPE_INGRESS, m::BNG_EGRESS] {
            assert!(
                obj.programs.contains_key(p),
                "program {p}: {:?}",
                obj.programs.keys()
            );
        }
        let text = String::from_utf8_lossy(super::super::OBJECT);
        assert!(!text.contains("panic_const"), "a panic path in the object");
    }

    #[test]
    fn subscriber_routes() {
        let mut p = corerouter_hal::pppoe::PppoeSession {
            ipv4: Some(Ipv4Addr::new(100, 64, 0, 9)),
            ipv6_prefix: Some([0x20, 1, 0xd, 0xb8, 0, 0, 0, 9]),
            delegated: Some(([0x20, 1, 0xd, 0xb8, 0x80, 0, 9, 0], 56)),
            mtu: 1480,
            ..Default::default()
        };
        let r = routes_of(&p);
        assert_eq!(
            r.iter()
                .map(|(n, m)| format!("{n} {m}"))
                .collect::<Vec<_>>(),
            [
                "100.64.0.9/32 1480",
                "2001:db8:0:9::/64 1480",
                "2001:db8:8000:900::/56 1480"
            ]
        );
        p.ipoe = true;
        assert!(routes_of(&p).is_empty(), "IPoE subscribers are on-link");
    }
}

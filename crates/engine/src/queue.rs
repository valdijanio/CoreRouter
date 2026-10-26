//! Queues (G4.9): the fixed `/queue simple` entries plus the dynamic ones
//! (PPPoE and IPoE sessions, DHCP leases), resolved into one [`Plan`]: which
//! queue holds which address, and what the operator should know about it.
//!
//! Precedence, in order:
//!
//! 1. A dynamic queue (a session, then a static lease's `rate_limit`, then
//!    a network's) takes its addresses from any fixed queue: the
//!    subscriber's plan wins over a broad fixed queue on the same address,
//!    and the overlap is warned.
//! 2. Fixed queues keep RouterOS's first match: a target inside an earlier
//!    queue's target never matches, so it is not installed and the queue is
//!    warned ("move it above"). With that rule a longest-prefix lookup (the
//!    data plane's trie) gives the same answer as RouterOS's walk.
//! 3. Address targets match before interface targets.
//!
//! Pure: [`plan`] takes the config and the dynamic queues and touches
//! nothing, so the daemon's `queue` service and the commands agree.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::Ipv4Addr;

use corerouter_hal::queue::QueueCounters;
use corerouter_model::queue::{
    DEFAULT_BUCKET, DEFAULT_DYNAMIC_TYPE, DEFAULT_PRIORITY, DownloadMode, Pair, QueueType,
    Queues, SimpleQueue, Target, TypeNames,
};
use corerouter_model::{Config, IfName};
use corerouter_proto_radius::rate_limit::RateLimit;
use ipnet::IpNet;

use crate::Session;

/// Where a queue comes from (the Origin chip of the Queues window).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Origin {
    Pppoe,
    Ipoe,
    DhcpLease,
    DhcpNetwork,
    Fixed,
}

impl Origin {
    pub const ALL: [Self; 5] = [
        Self::Fixed,
        Self::Pppoe,
        Self::Ipoe,
        Self::DhcpLease,
        Self::DhcpNetwork,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pppoe => "pppoe",
            Self::Ipoe => "ipoe",
            Self::DhcpLease => "dhcp-lease",
            Self::DhcpNetwork => "dhcp-network",
            Self::Fixed => "fixed",
        }
    }

    pub fn parse(t: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|o| o.as_str() == t.trim())
    }

    pub fn dynamic(self) -> bool {
        self != Self::Fixed
    }

    /// A session's queue lives in the subscriber maps (the BNG service
    /// programs it with the session); the others in the queue maps.
    pub fn session(self) -> bool {
        matches!(self, Self::Pppoe | Self::Ipoe)
    }
}

/// One direction of a queue, resolved: rates in bits per second, the
/// burst window in ms, the bucket in thousandths of the rate, and the
/// queue type itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limit {
    pub max_limit: u64,
    pub limit_at: u64,
    pub burst_limit: u64,
    pub burst_threshold: u64,
    pub burst_time_ms: u32,
    pub bucket_milli: u32,
    pub priority: u8,
    pub queue: QueueType,
}

impl Limit {
    fn of(q: &SimpleQueue, types: &Queues, download: bool) -> Self {
        let name = q.queue.get(download);
        Self {
            max_limit: q.max_limit.get(download),
            limit_at: q.limit_at.get(download),
            burst_limit: q.burst_limit.get(download),
            burst_threshold: q.burst_threshold.get(download),
            burst_time_ms: q.burst_time.get(download),
            bucket_milli: q.bucket_size.get(download),
            priority: q.priority.get(download),
            queue: types
                .queue_type(name)
                .unwrap_or_else(|| QueueType::new(name, corerouter_model::queue::Kind::Pfifo)),
        }
    }

    /// One direction of a RouterOS `rate-limit` (profile, RADIUS,
    /// lease). `rx` is the subscriber's upload.
    pub fn of_rate_limit(r: &RateLimit, download: bool, queue: QueueType) -> Self {
        let pick = |p: corerouter_proto_radius::rate_limit::Pair<u64>| {
            if download { p.tx } else { p.rx }
        };
        Self {
            max_limit: pick(r.rate),
            limit_at: r.min_rate.map(pick).unwrap_or(0),
            burst_limit: r.burst_rate.map(pick).unwrap_or(0),
            burst_threshold: r.burst_threshold.map(pick).unwrap_or(0),
            burst_time_ms: r
                .burst_time
                .map(|t| if download { t.tx } else { t.rx })
                .unwrap_or(0)
                .saturating_mul(1000),
            bucket_milli: DEFAULT_BUCKET,
            priority: r.priority.unwrap_or(DEFAULT_PRIORITY),
            queue,
        }
    }
}

/// A queue, fixed or dynamic, resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Queue {
    /// `*5` (a fixed queue's id), `ppp:<session id>`, `dhcp:<address>`.
    pub key: String,
    pub name: String,
    pub origin: Origin,
    pub disabled: bool,
    pub targets: Vec<Target>,
    pub upload: Limit,
    pub download: Limit,
    pub download_mode: DownloadMode,
    pub comment: String,
    /// Type names as written (the row shows them).
    pub queue_names: TypeNames,
}

impl Queue {
    pub fn limit(&self, download: bool) -> &Limit {
        if download { &self.download } else { &self.upload }
    }

    fn fixed(q: &SimpleQueue, types: &Queues) -> Self {
        Self {
            key: q.id.to_string(),
            name: q.name.clone(),
            origin: Origin::Fixed,
            disabled: q.disabled,
            targets: q.target.clone(),
            upload: Limit::of(q, types, false),
            download: Limit::of(q, types, true),
            download_mode: DownloadMode::Shaper,
            comment: q.comment.clone(),
            queue_names: q.queue.clone(),
        }
    }

    /// A dynamic queue from a RouterOS `rate-limit` text: `None` when the
    /// text does not parse (the origin refused it already).
    #[allow(clippy::too_many_arguments)]
    pub fn dynamic(
        key: String,
        name: String,
        origin: Origin,
        targets: Vec<Target>,
        rate_limit: &str,
        types: &Queues,
        queue_type: &str,
        download_mode: DownloadMode,
    ) -> Option<Self> {
        let r: RateLimit = rate_limit.trim().parse().ok()?;
        let qt = types
            .queue_type(queue_type)
            .or_else(|| types.queue_type(DEFAULT_DYNAMIC_TYPE))
            .unwrap_or_else(|| QueueType::new(DEFAULT_DYNAMIC_TYPE, corerouter_model::queue::Kind::FqCodel));
        // The upload is always the XDP policer: its type is only shown.
        Some(Self {
            key,
            name,
            origin,
            disabled: false,
            targets,
            upload: Limit::of_rate_limit(&r, false, qt.clone()),
            download: Limit::of_rate_limit(&r, true, qt.clone()),
            download_mode,
            comment: String::new(),
            queue_names: TypeNames::both(&qt.name),
        })
    }
}

/// The resolved queues and what is installed where.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Plan {
    /// Dynamic queues first (they win), then the fixed ones in order;
    /// disabled fixed queues are kept (the list shows them) but install
    /// nothing.
    pub queues: Vec<Queue>,
    /// Address targets installed: prefix → index in `queues`.
    pub prefixes: BTreeMap<IpNet, usize>,
    /// Interface targets installed: interface → index in `queues`.
    pub interfaces: BTreeMap<IfName, usize>,
    /// Warnings by index in `queues`.
    pub warnings: BTreeMap<usize, Vec<String>>,
}

impl Plan {
    fn warn(&mut self, i: usize, w: String) {
        let v = self.warnings.entry(i).or_default();
        // Thousands of sessions inside one fixed queue: say it once.
        if v.len() < 8 && !v.contains(&w) {
            v.push(w);
        }
    }

    pub fn warnings_of(&self, i: usize) -> &[String] {
        self.warnings.get(&i).map(Vec::as_slice).unwrap_or(&[])
    }
}

/// The fixed queues of `cfg`, in order.
pub fn fixed(cfg: &Config) -> Vec<Queue> {
    cfg.queue
        .simple
        .iter()
        .map(|q| Queue::fixed(q, &cfg.queue))
        .collect()
}

/// The installed prefix of `cover` that holds `n` (equal or wider), if
/// any: at most 33 (or 129) hash probes, so checking every session of a
/// big BNG against the fixed queues stays linear.
fn covering(set: &HashMap<IpNet, usize>, n: &IpNet) -> Option<(IpNet, usize)> {
    (0..=n.prefix_len()).rev().find_map(|len| {
        let p = IpNet::new(n.network(), len).ok()?.trunc();
        set.get(&p).map(|i| (p, *i))
    })
}

/// Resolve `cfg`'s fixed queues and `dynamic` into a plan.
pub fn plan(cfg: &Config, mut dynamic: Vec<Queue>) -> Plan {
    dynamic.sort_by_key(|q| q.origin);
    let n_dyn = dynamic.len();
    let mut p = Plan {
        queues: dynamic,
        ..Plan::default()
    };
    p.queues.extend(fixed(cfg));
    // Fixed first (first match), so the dynamic ones can be checked
    // against what the fixed queues would hold.
    let mut fixed_at: HashMap<IpNet, usize> = HashMap::new();
    let mut fixed_if: HashMap<IfName, usize> = HashMap::new();
    for i in n_dyn..p.queues.len() {
        let Some(q) = p.queues.get(i).cloned() else {
            continue;
        };
        if q.disabled {
            continue;
        }
        for t in &q.targets {
            match t {
                Target::Prefix(n) => {
                    if let Some((wider, j)) = covering(&fixed_at, n) {
                        let other = p.queues.get(j).map(|o| o.name.clone()).unwrap_or_default();
                        let what = if wider == *n { "the same target as" } else { "inside the target of" };
                        p.warn(i, format!("{n} is {what} queue '{other}' above it: it never matches here (move this queue above '{other}')"));
                        continue;
                    }
                    fixed_at.insert(*n, i);
                }
                Target::Interface(name) => {
                    if let Some(j) = fixed_if.get(name) {
                        let other = p.queues.get(*j).map(|o| o.name.clone()).unwrap_or_default();
                        p.warn(i, format!("interface {name} is already the target of queue '{other}' above it"));
                        continue;
                    }
                    fixed_if.insert(name.clone(), i);
                }
            }
        }
    }
    // Dynamic queues: one per address; the first origin wins a tie.
    let mut dyn_at: HashMap<IpNet, usize> = HashMap::new();
    let mut overlapped: HashSet<(usize, usize)> = HashSet::new();
    for i in 0..n_dyn {
        let Some(q) = p.queues.get(i).cloned() else {
            continue;
        };
        for t in &q.targets {
            let Target::Prefix(n) = t else {
                continue;
            };
            if let Some(j) = dyn_at.get(n) {
                let other = p.queues.get(*j).map(|o| (o.name.clone(), o.origin)).unwrap_or((String::new(), Origin::Fixed));
                p.warn(i, format!("{n} is held by {} queue '{}': this one does not apply", other.1.as_str(), other.0));
                continue;
            }
            dyn_at.insert(*n, i);
            if let Some((_, j)) = covering(&fixed_at, n)
                && overlapped.insert((i, j))
            {
                let fixed_name = p.queues.get(j).map(|o| o.name.clone()).unwrap_or_default();
                p.warn(i, format!("takes {n} from fixed queue '{fixed_name}' (a {} queue wins on its own address)", q.origin.as_str()));
                p.warn(j, format!("{} queue '{}' takes {n} (dynamic queues win on their addresses)", q.origin.as_str(), q.name));
            }
        }
    }
    // A fixed target equal to a dynamic one is taken by the dynamic queue.
    for (n, i) in &dyn_at {
        fixed_at.remove(n);
        p.prefixes.insert(*n, *i);
    }
    p.prefixes.extend(fixed_at);
    p.interfaces = fixed_if.into_iter().collect();
    p
}

/// The DHCP leases that make a queue (RouterOS: a static lease with
/// `rate-limit`; here also a network's `rate_limit`): bound leases of
/// servers whose leases are not subscriber sessions (those are PPP
/// sessions, G4.3f).
pub fn dhcp_dynamic(s: &Session) -> Vec<Queue> {
    let cfg = s.store().running();
    let d = &cfg.ip.dhcp_server;
    let has_rates = d.leases.iter().any(|l| !l.rate_limit.is_empty())
        || d.networks.iter().any(|n| !n.rate_limit.is_empty());
    let Some(core) = s.dhcp_server().filter(|_| has_rates) else {
        return Vec::new();
    };
    let sessions: HashSet<&str> = d
        .servers
        .iter()
        .filter(|v| v.sessions())
        .map(|v| v.name.as_str())
        .collect();
    let statics: HashMap<Ipv4Addr, &corerouter_model::dhcp_server::StaticLease> = d
        .leases
        .iter()
        .filter(|l| !l.disabled && !l.rate_limit.is_empty())
        .map(|l| (l.address, l))
        .collect();
    let mut out = Vec::new();
    for l in core.leases().iter() {
        if l.state != corerouter_proto_dhcp::server::leases::State::Bound || sessions.contains(l.server.as_str()) {
            continue;
        }
        let (origin, rate) = match statics.get(&l.address) {
            Some(st) if st.server.as_deref().is_none_or(|v| v == l.server) => (Origin::DhcpLease, st.rate_limit.as_str()),
            _ => match d.networks.iter().find(|n| !n.rate_limit.is_empty() && n.address.contains(&l.address)) {
                Some(n) => (Origin::DhcpNetwork, n.rate_limit.as_str()),
                None => continue,
            },
        };
        let who = if l.host_name.is_empty() {
            let [a, b, c, e, f, g] = l.mac;
            format!("{a:02X}:{b:02X}:{c:02X}:{e:02X}:{f:02X}:{g:02X}")
        } else {
            l.host_name.clone()
        };
        if let Some(q) = Queue::dynamic(
            format!("dhcp:{}", l.address),
            // RouterOS names them so.
            format!("dhcp-ds<{who}>"),
            origin,
            vec![Target::Prefix(IpNet::from(std::net::IpAddr::V4(l.address)))],
            rate,
            &cfg.queue,
            DEFAULT_DYNAMIC_TYPE,
            DownloadMode::Shaper,
        ) {
            out.push(q);
        }
    }
    out
}

/// The queue of an active PPP session (PPPoE or IPoE), from its rate
/// limit and its profile's queue settings; `None` without a rate limit.
pub fn session_queue(cfg: &Config, a: &corerouter_model::ppp::ActiveSession) -> Option<Queue> {
    let rate = a.rate_limit.as_deref()?;
    let e = cfg.ppp.effective(None, &a.profile, corerouter_model::ppp::DEFAULT_PROFILE);
    let mut targets = Vec::new();
    if let Some(ip) = a.address {
        targets.push(Target::Prefix(IpNet::from(std::net::IpAddr::V4(ip))));
    }
    for n in [a.ipv6_prefix, a.delegated_prefix].into_iter().flatten() {
        targets.push(Target::Prefix(IpNet::V6(n)));
    }
    let origin = if a.service == "ipoe" { Origin::Ipoe } else { Origin::Pppoe };
    let name = if a.service == "ipoe" { format!("<ipoe-{}>", a.name) } else { format!("<pppoe-{}>", a.name) };
    Queue::dynamic(format!("ppp:{}", a.id), name, origin, targets, rate, &cfg.queue, &e.queue_type, e.download_mode)
}

/// Counters the daemon's `queue` service reads from the data plane, by
/// queue key (not config: gone on restart).
#[derive(Debug, Default)]
pub struct QueueStats {
    pub by_key: HashMap<String, QueueCounters>,
    /// Whether a data plane is shaping (the virtual lab has none).
    pub running: bool,
    /// Why not, when it is not.
    pub note: Option<String>,
}

impl Session {
    /// The plan of the running config with the DHCP leases' queues (the
    /// sessions' queues live in the subscriber maps; [`plan_with_sessions`]
    /// adds them for the list and its warnings).
    pub fn queue_plan(&self) -> Plan {
        plan(self.store().running(), dhcp_dynamic(self))
    }

    pub fn queue_counters(&self, key: &str) -> Option<QueueCounters> {
        self.ext::<QueueStats>()?.by_key.get(key).copied()
    }
}

/// `plan` plus the queues of `sessions` (the list shows them; their
/// overlaps with fixed queues are warned).
pub fn plan_with_sessions(s: &Session, sessions: &[corerouter_model::ppp::ActiveSession]) -> Plan {
    let cfg = s.store().running();
    let mut dynamic: Vec<Queue> = sessions.iter().filter_map(|a| session_queue(cfg, a)).collect();
    dynamic.extend(dhcp_dynamic(s));
    plan(cfg, dynamic)
}

/// Pair helper for rows: `up/down` of `f` over both directions.
pub fn pair_of<T: Copy>(q: &Queue, f: impl Fn(&Limit) -> T) -> Pair<T> {
    Pair {
        upload: f(&q.upload),
        download: f(&q.download),
    }
}


// --- To the data plane (G4.9b) ---------------------------------------------

/// What a queue type does, as the shaper runs it.
pub fn kind_of(t: &QueueType) -> corerouter_hal::queue::Kind {
    use corerouter_hal::queue::Kind as K;
    use corerouter_model::queue::Kind;
    match t.kind {
        Kind::Pfifo => K::Fifo {
            limit_bytes: u64::from(t.pfifo_limit) * 1514,
        },
        Kind::Bfifo => K::Fifo {
            limit_bytes: u64::from(t.bfifo_limit),
        },
        // The queue's own clock caps all the sub-streams together.
        Kind::Pcq => K::Fifo {
            limit_bytes: u64::from(t.pcq_total_limit) * 1024,
        },
        Kind::FqCodel => K::Codel {
            target_us: t.fq_codel_target.saturating_mul(1000),
            interval_us: t.fq_codel_interval.saturating_mul(1000),
            ecn: t.fq_codel_ecn,
            limit_packets: t.fq_codel_limit,
        },
        // CAKE's CoDel follows its RTT: target = rtt/20 (5 ms at 100 ms),
        // interval = rtt; it always marks ECN.
        Kind::Cake => K::Codel {
            target_us: (t.cake_rtt.saturating_mul(1000) / 20).max(500),
            interval_us: t.cake_rtt.saturating_mul(1000),
            ecn: true,
            limit_packets: corerouter_model::queue::FQ_CODEL_LIMIT,
        },
    }
}

fn pcq_of(t: &QueueType) -> Option<corerouter_hal::queue::PcqSpec> {
    use corerouter_model::queue::{Classifier, Kind};
    if t.kind != Kind::Pcq {
        return None;
    }
    let by_src = t.pcq_classifier == Classifier::SrcAddress;
    Some(corerouter_hal::queue::PcqSpec {
        rate_bps: t.pcq_rate,
        by_src,
        mask4: if by_src { t.pcq_src_address_mask } else { t.pcq_dst_address_mask },
        mask6: if by_src { t.pcq_src_address6_mask } else { t.pcq_dst_address6_mask },
        kind: corerouter_hal::queue::Kind::Fifo {
            limit_bytes: u64::from(t.pcq_limit) * 1024,
        },
    })
}

fn dir_of(l: &Limit) -> corerouter_hal::queue::DirSpec {
    corerouter_hal::queue::DirSpec {
        rate_bps: l.max_limit,
        burst_bps: l.burst_limit,
        threshold_bps: l.burst_threshold,
        burst_time_ms: l.burst_time_ms,
        bucket_milli: l.bucket_milli,
        kind: kind_of(&l.queue),
        pcq: pcq_of(&l.queue),
    }
}

/// The interfaces whose connected networks hold `n` (`None`: none does,
/// the target is somewhere behind a route).
fn ports_of(cfg: &Config, n: &IpNet) -> Option<Vec<IfName>> {
    let v: Vec<IfName> = cfg
        .ip
        .addresses
        .iter()
        .filter(|a| !a.disabled)
        .filter(|a| {
            let net = a.address.trunc();
            net.contains(&n.network()) || n.contains(&net.network())
        })
        .map(|a| a.interface.clone())
        .collect();
    (!v.is_empty()).then_some(v)
}

/// `plan` as the shaper holds it: the queues that are not sessions (those
/// ride on their session entries), their targets, and the ports to shape
/// on. A target no connected network holds is reached through some route:
/// every port gets the programs then (a lookup per packet, ~30 ns,
/// **estimado**), rather than a target left unshaped.
pub fn shaper_plan(cfg: &Config, plan: &Plan) -> corerouter_hal::queue::ShaperPlan {
    use corerouter_hal::queue::{QueueSpec, ShaperPlan};
    let mut slot_of: HashMap<usize, u32> = HashMap::new();
    let mut out = ShaperPlan::default();
    let used: std::collections::BTreeSet<usize> = plan.prefixes.values().chain(plan.interfaces.values()).copied().collect();
    for i in used {
        let Some(q) = plan.queues.get(i) else {
            continue;
        };
        if q.origin.session() || q.disabled {
            continue;
        }
        let Ok(slot) = u32::try_from(out.queues.len()) else {
            break;
        };
        slot_of.insert(i, slot);
        out.queues.push(QueueSpec {
            key: q.key.clone(),
            upload: dir_of(&q.upload),
            download: dir_of(&q.download),
        });
    }
    let mut ports: std::collections::BTreeSet<IfName> = std::collections::BTreeSet::new();
    let mut everywhere = false;
    for (n, i) in &plan.prefixes {
        if let Some(slot) = slot_of.get(i) {
            out.prefixes.push((*n, *slot));
            match ports_of(cfg, n) {
                Some(v) => ports.extend(v),
                None => everywhere = true,
            }
        }
    }
    for (name, i) in &plan.interfaces {
        if let Some(slot) = slot_of.get(i) {
            out.interfaces.push((name.clone(), *slot));
            ports.insert(name.clone());
        }
    }
    let d = &cfg.ip.dhcp_server;
    let ipoe: Vec<IfName> = d.servers.iter().filter(|v| !v.disabled && v.sessions()).map(|v| v.interface.clone()).collect();
    let pppoe: Vec<IfName> = cfg.ppp.pppoe_servers.iter().filter(|v| !v.disabled).map(|v| v.interface.clone()).collect();
    out.access_ports = pppoe.into_iter().chain(ipoe).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
    out.sessions = !out.access_ports.is_empty();
    if everywhere && !out.queues.is_empty() {
        ports.extend(
            cfg.interfaces
                .iter()
                .filter(|(_, i)| !i.disabled && !matches!(i.kind, corerouter_model::InterfaceKind::Loopback))
                .map(|(n, _)| n.clone()),
        );
    }
    out.ports = ports.into_iter().collect();
    out
}

/// The download queue a session gets from its profile: `None` when the
/// profile polices (`download_mode=policer`), else its queue type's kind
/// (an unknown type: the recommended fq-codel).
pub fn shape_of(queues: &Queues, e: &corerouter_model::ppp::Effective) -> Option<corerouter_hal::queue::Kind> {
    if e.download_mode != DownloadMode::Shaper {
        return None;
    }
    Some(queues.queue_type(&e.queue_type).map(|t| kind_of(&t)).unwrap_or_default())
}

/// What the daemon's `queue` service last handed to the HAL.
#[derive(Debug, Default)]
pub struct ShaperRuntime {
    pub applied: Option<corerouter_hal::queue::ShaperPlan>,
    pub error: Option<String>,
}

impl Session {
    /// One round of the `queue` service: the plan of the running config
    /// and the DHCP leases to the data plane (only when it changed), then
    /// the counters back into [`QueueStats`]. Returns whether the plan was
    /// (re)applied.
    pub fn queue_sync(&mut self) -> bool {
        let plan = self.queue_plan();
        let want = shaper_plan(self.store().running(), &plan);
        let rt = self.ext::<ShaperRuntime>();
        let changed = rt.is_none_or(|r| r.applied.as_ref() != Some(&want));
        if changed {
            let res = self.hal_mut().shaper_apply(&want);
            if let Some(rt) = self.ext_mut::<ShaperRuntime>() {
                rt.error = res.err().map(|e| e.to_string());
                rt.applied = Some(want);
            }
        }
        let status = self.hal_mut().shaper_status();
        let error = self.ext::<ShaperRuntime>().and_then(|r| r.error.clone());
        if let Some(st) = self.ext_mut::<QueueStats>() {
            st.by_key = status.queues.into_iter().collect();
            st.running = status.unavailable.is_none() && error.is_none();
            st.note = error.or(status.unavailable);
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use corerouter_model::ItemId;
    use corerouter_model::queue::parse_targets;

    fn cfg(queues: &[(&str, &str)]) -> Config {
        let mut c = Config::default();
        for (i, (name, target)) in queues.iter().enumerate() {
            let mut q = SimpleQueue::new(ItemId(i as u32 + 1), (*name).into(), parse_targets(target).unwrap());
            q.max_limit = "10M/20M".parse().unwrap();
            c.queue.simple.push(q);
        }
        c
    }

    fn dynq(name: &str, origin: Origin, ip: &str) -> Queue {
        Queue::dynamic(
            format!("k:{name}"),
            name.into(),
            origin,
            parse_targets(ip).unwrap(),
            "5M/50M",
            &Queues::default(),
            DEFAULT_DYNAMIC_TYPE,
            DownloadMode::Shaper,
        )
        .unwrap()
    }

    fn at(p: &Plan, n: &str) -> Option<String> {
        let n: IpNet = n.parse().unwrap();
        p.prefixes.get(&n).map(|i| p.queues[*i].name.clone())
    }

    #[test]
    fn first_match_becomes_longest_prefix() {
        // A broad queue above a narrow one hides it (RouterOS first match).
        let p = plan(&cfg(&[("lan", "10.0.0.0/16"), ("cam", "10.0.1.5")]), vec![]);
        assert_eq!(at(&p, "10.0.0.0/16").as_deref(), Some("lan"));
        assert_eq!(at(&p, "10.0.1.5/32"), None);
        assert!(p.warnings_of(1)[0].contains("never matches"), "{:?}", p.warnings);
        // Narrow above broad: both installed, the trie picks the narrow.
        let p = plan(&cfg(&[("cam", "10.0.1.5"), ("lan", "10.0.0.0/16")]), vec![]);
        assert_eq!(at(&p, "10.0.1.5/32").as_deref(), Some("cam"));
        assert_eq!(at(&p, "10.0.0.0/16").as_deref(), Some("lan"));
        assert!(p.warnings.is_empty());
    }

    #[test]
    fn dynamic_wins_and_warns_both() {
        let p = plan(
            &cfg(&[("clients", "100.64.0.0/10")]),
            vec![dynq("<pppoe-ana>", Origin::Pppoe, "100.64.0.9"), dynq("dhcp-ds<x>", Origin::DhcpLease, "100.64.0.9")],
        );
        assert_eq!(at(&p, "100.64.0.9/32").as_deref(), Some("<pppoe-ana>"));
        assert_eq!(at(&p, "100.64.0.0/10").as_deref(), Some("clients"));
        // The session first; the lease on the same address is refused.
        assert!(p.warnings_of(0)[0].contains("takes 100.64.0.9/32 from fixed queue 'clients'"), "{:?}", p.warnings);
        assert!(p.warnings_of(1)[0].contains("held by pppoe queue"), "{:?}", p.warnings);
        assert!(p.warnings_of(2)[0].contains("pppoe queue '<pppoe-ana>' takes"), "{:?}", p.warnings);
        // An equal fixed target is taken.
        let p = plan(&cfg(&[("one", "10.0.0.7")]), vec![dynq("dhcp-ds<y>", Origin::DhcpNetwork, "10.0.0.7")]);
        assert_eq!(at(&p, "10.0.0.7/32").as_deref(), Some("dhcp-ds<y>"));
    }

    #[test]
    fn disabled_and_interfaces() {
        let mut c = cfg(&[("off", "10.0.0.0/8"), ("a", "ether2"), ("b", "ether2,10.1.0.0/16")]);
        c.queue.simple.get_mut(0).unwrap().disabled = true;
        let p = plan(&c, vec![]);
        assert_eq!(at(&p, "10.1.0.0/16").as_deref(), Some("b"), "a disabled queue hides nothing");
        assert_eq!(p.interfaces.len(), 1);
        assert!(p.warnings_of(2)[0].contains("interface ether2"));
    }

    #[test]
    fn rate_limit_text_becomes_limits() {
        let q = Queue::dynamic(
            "k".into(),
            "n".into(),
            Origin::Pppoe,
            vec![],
            "10M/50M 20M/80M 8M/40M 16/8 5 2M/10M",
            &Queues::default(),
            "cake-default",
            DownloadMode::Policer,
        )
        .unwrap();
        assert_eq!((q.upload.max_limit, q.download.max_limit), (10_000_000, 50_000_000));
        assert_eq!((q.upload.burst_limit, q.download.burst_limit), (20_000_000, 80_000_000));
        assert_eq!((q.upload.burst_threshold, q.download.burst_threshold), (8_000_000, 40_000_000));
        assert_eq!((q.upload.burst_time_ms, q.download.burst_time_ms), (16_000, 8_000));
        assert_eq!((q.download.priority, q.download.limit_at), (5, 10_000_000));
        assert_eq!(q.download.queue.name, "cake-default");
        // An unknown type falls back to the recommended one.
        let q = Queue::dynamic("k".into(), "n".into(), Origin::Pppoe, vec![], "1M", &Queues::default(), "nope", DownloadMode::Shaper).unwrap();
        assert_eq!(q.download.queue.name, DEFAULT_DYNAMIC_TYPE);
        assert!(Queue::dynamic("k".into(), "n".into(), Origin::Pppoe, vec![], "fast", &Queues::default(), "x", DownloadMode::Shaper).is_none());
    }

    #[test]
    fn shaper_plan_ports_and_kinds() {
        let mut c = Session::virtual_lab().store().running().clone();
        c.queue = cfg(&[("lan", "192.168.88.0/24"), ("far", "203.0.113.0/24"), ("off", "10.9.9.9")]).queue;
        c.queue.simple.get_mut(2).unwrap().disabled = true;
        c.ip.addresses = corerouter_model::cow_list::CowList::from(vec![corerouter_model::AddressEntry {
            id: ItemId(1),
            address: "192.168.88.1/24".parse().unwrap(),
            interface: "ether2".parse().unwrap(),
            disabled: false,
            comment: String::new(),
            from_pool: None,
        }]);
        let p = plan(&c, vec![]);
        let s = shaper_plan(&c, &p);
        assert_eq!(s.queues.len(), 2, "the disabled one installs nothing");
        // "far" is behind a route: every port gets the programs.
        assert!(s.ports.len() > 1 && s.ports.iter().any(|p| p.as_str() == "ether2"));
        assert!(!s.sessions);
        let lan = s.queues.iter().find(|q| q.key == "*1").unwrap();
        assert_eq!(lan.download.rate_bps, 20_000_000);
        assert_eq!(lan.download.kind, corerouter_hal::queue::Kind::Fifo { limit_bytes: 10 * 1514 });
        let cake = kind_of(&QueueType::builtin("cake-default").unwrap());
        assert_eq!(cake, corerouter_hal::queue::Kind::Codel { target_us: 5_000, interval_us: 100_000, ecn: true, limit_packets: 10_240 });
        let pcq = pcq_of(&QueueType::builtin("pcq-upload-default").unwrap()).unwrap();
        assert!(pcq.by_src);
        // Only the connected one: just its port.
        c.queue.simple.remove(1);
        let s = shaper_plan(&c, &plan(&c, vec![]));
        assert_eq!(s.ports.iter().map(|p| p.as_str()).collect::<Vec<_>>(), ["ether2"]);
    }

    /// 100 000 sessions against 1 000 fixed queues: linear, not a product.
    #[test]
    fn big_plans_stay_linear() {
        let mut c = Config::default();
        for i in 0..1000u32 {
            let t = format!("10.{}.{}.0/24", i / 256, i % 256);
            c.queue.simple.push(SimpleQueue::new(ItemId(i + 1), format!("q{i}"), parse_targets(&t).unwrap()));
        }
        let dynamic: Vec<Queue> = (0..100_000u32)
            .map(|i| {
                let ip = Ipv4Addr::from(0x0a00_0000 + i);
                let mut q = dynq("s", Origin::Pppoe, &ip.to_string());
                q.key = format!("ppp:{i}");
                q
            })
            .collect();
        let t = std::time::Instant::now();
        let p = plan(&c, dynamic);
        assert_eq!(p.prefixes.len(), 101_000);
        assert!(t.elapsed().as_secs_f64() < 5.0, "{:?}", t.elapsed());
    }
}

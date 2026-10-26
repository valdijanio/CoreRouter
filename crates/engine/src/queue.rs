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
        c.queue.simple[0].disabled = true;
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

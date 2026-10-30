//! Check-gateway (RouterOS `check-gateway`): is a route's gateway alive?
//! While it is not, the route leaves the data plane and the next distance
//! takes over; when it answers again, the route comes back.
//!
//! One mechanism for every route that has a check:
//!
//! - [`Health`]: the state machine — down after [`CHECK_MISSES`]
//!   unanswered checks, up at the first answer, with a hold-down that
//!   grows with the flaps of the last [`FLAP_WINDOW_MS`] (a gateway that
//!   comes and goes must not move the traffic back and forth every 10 s);
//!   the DHCP client's lease gateway (G4.7c, [`crate::dhcp_resilience`])
//!   and static routes (G1.27f) both use it;
//! - static routes (G1.27f, G3.6g): [`Target`] groups the routes by what
//!   is checked (method, gateway, table): a thousand routes through one
//!   gateway cost one probe. The engine keeps their [`Health`] and pulls
//!   the routes of a down target out of [`Session::effective`]; the
//!   probes themselves run on the daemon's `route-check` thread, outside
//!   the session lock, with [`Schedule`] deciding when each one leaves.
//!   `bfd` has no probe: the state is the one of the BFD session the
//!   `bfd` service runs to the gateway (`routing.bfd.session.list`).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, Ipv4Addr};

use corerouter_model::bfd::{BfdState, PROFILE_DEFAULT};
use corerouter_model::dhcp_client::CheckGateway;
use corerouter_model::route::{self, Reach};
use corerouter_model::{Config, IfName, ItemId, RouteEntry, RoutingTable};
use serde_json::{Value, json};

use crate::Session;
use crate::dhcp_resilience::RouteCheck;

/// RouterOS' `check-gateway`: one check every 10 s, the gateway is down
/// after 2 unanswered ones and up again at the first answer.
pub const CHECK_INTERVAL_MS: u64 = 10_000;
pub const CHECK_MISSES: u32 = 2;
/// How long one check waits for its answer (RouterOS' ping timeout is 1 s;
/// a busy CPE answers ARP late, **estimado**).
pub const CHECK_WAIT_MS: u64 = 2_000;
/// Downs counted for the hold-down: those of the last 15 minutes.
pub const FLAP_WINDOW_MS: u64 = 15 * 60_000;
/// Hold-down after the second down of the window; it doubles with each
/// further one, up to [`HOLD_MAX_MS`]. The first down comes back at the
/// first answer, as in RouterOS.
pub const HOLD_BASE_MS: u64 = CHECK_INTERVAL_MS;
pub const HOLD_MAX_MS: u64 = 5 * 60_000;
/// Downs remembered per target (only the window's count).
const MAX_DOWNS: usize = 16;
/// The targets are taken again at least this often even when the config
/// did not change (a DHCP lease moved the ARP source address).
pub const RESYNC_MS: u64 = 10_000;
/// Check transitions logged one by one per report; the rest in one line
/// (the uplink switch dies: 10 000 gateways down at once).
const MAX_LOG_LINES: usize = 16;
/// A BFD session that has not come up this long after its route asked for
/// it counts as down (RFC 5880 §6.8.3: before Up, packets go at most once
/// a second; three of them and an answer fit, **estimado**).
pub const BFD_GRACE_MS: u64 = 5_000;
/// Static route check transitions kept for `ip.route.check.history`.
pub const MAX_HISTORY: usize = 1_000;
/// Check targets at most (hostile-input bound: the routes already are).
pub const MAX_TARGETS: usize = 65_536;

/// Whether a gateway answers, over time.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Health {
    /// Checks unanswered in a row.
    pub misses: u32,
    /// Its routes are withheld.
    pub down: bool,
    /// Clock (ms) when it went down.
    pub down_since: Option<u64>,
    /// One check finished (false: still "checking").
    pub known: bool,
    /// Answering again since (ms) while held down.
    pub up_since: Option<u64>,
    /// When it last changed (ms).
    pub last_change: Option<u64>,
    /// When the check started (ms).
    pub since: u64,
    downs: VecDeque<u64>,
}

impl Health {
    /// A check answered at `now`; true when the routes come back.
    pub fn answered(&mut self, now: u64) -> bool {
        self.known = true;
        self.misses = 0;
        if !self.down {
            return false;
        }
        let since = *self.up_since.get_or_insert(now);
        if now.saturating_sub(since) < self.hold_ms(now) {
            return false;
        }
        self.down = false;
        self.down_since = None;
        self.up_since = None;
        self.last_change = Some(now);
        true
    }

    /// A check went unanswered at `now`; true when the routes leave.
    pub fn missed(&mut self, now: u64) -> bool {
        self.misses = self.misses.saturating_add(1);
        self.fail_after(now, CHECK_MISSES)
    }

    /// Down at once (a BFD session that went down: BFD already waited its
    /// detect time); true when the routes leave.
    pub fn failed(&mut self, now: u64) -> bool {
        self.misses = self.misses.saturating_add(1);
        self.fail_after(now, 1)
    }

    fn fail_after(&mut self, now: u64, needed: u32) -> bool {
        self.known = true;
        self.up_since = None;
        if self.down || self.misses < needed {
            return false;
        }
        self.down = true;
        self.down_since = Some(now);
        self.last_change = Some(now);
        self.downs.push_back(now);
        while self.downs.len() > MAX_DOWNS {
            self.downs.pop_front();
        }
        true
    }

    /// Downs in the window ending at `now`.
    pub fn flaps(&self, now: u64) -> usize {
        self.downs
            .iter()
            .filter(|t| now.saturating_sub(**t) <= FLAP_WINDOW_MS)
            .count()
    }

    /// How long the gateway must keep answering before its routes come back.
    pub fn hold_ms(&self, now: u64) -> u64 {
        match self.flaps(now) {
            0 | 1 => 0,
            n => {
                let shift = u32::try_from(n.saturating_sub(2)).unwrap_or(u32::MAX).min(10);
                HOLD_BASE_MS.saturating_mul(1 << shift).min(HOLD_MAX_MS)
            }
        }
    }

    /// Hold-down left (answering, still down), in ms.
    pub fn hold_left_ms(&self, now: u64) -> Option<u64> {
        let since = self.up_since.filter(|_| self.down)?;
        Some(self.hold_ms(now).saturating_sub(now.saturating_sub(since)))
    }

    /// `checking` | `reachable` | `unreachable`.
    pub fn status(&self) -> &'static str {
        match (self.known, self.down) {
            (_, true) => "unreachable",
            (false, false) => "checking",
            (true, false) => "reachable",
        }
    }
}

/// What one check looks at: routes with the same target share its probe.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Target {
    pub method: CheckGateway,
    pub gateway: IpAddr,
    /// The interface of an `ip%interface` gateway.
    pub interface: Option<IfName>,
    pub table: RoutingTable,
    /// BFD profile (`bfd` only).
    pub profile: String,
}

impl Target {
    pub fn text(&self) -> String {
        match &self.interface {
            Some(i) => format!("{}%{i}", self.gateway),
            None => self.gateway.to_string(),
        }
    }
}

/// The check of route `r`, if it has one and can have one.
pub fn target_of(r: &RouteEntry) -> Option<Target> {
    if r.check_gateway == CheckGateway::None || r.disabled {
        return None;
    }
    let gateway = r.gateway.address()?;
    let profile = match r.check_gateway {
        CheckGateway::Bfd if r.bfd_profile.is_empty() => PROFILE_DEFAULT.to_owned(),
        CheckGateway::Bfd => r.bfd_profile.clone(),
        _ => String::new(),
    };
    Some(Target {
        method: r.check_gateway,
        gateway,
        interface: r.gateway.iface().cloned(),
        table: r.routing_table.clone(),
        profile,
    })
}

/// How the `route-check` thread probes one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeHow {
    /// ICMP echo; `device`: the interface of `ip%interface`, or the VRF.
    Ping { device: Option<String> },
    /// ARP request out of `link`, from `src` (0.0.0.0: an RFC 5227 probe,
    /// for a link without an address in the gateway's subnet).
    Arp { link: IfName, src: Ipv4Addr },
    /// Nothing can be sent (no link, link down): every check is a miss.
    Unreachable(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeTarget {
    pub target: Target,
    pub how: ProbeHow,
}

/// One check transition (`ip.route.check.history`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckEvent {
    /// Unix seconds, when the router has a clock.
    pub time: Option<u64>,
    pub target: Target,
    /// `up` | `down`.
    pub to: &'static str,
    pub routes: usize,
    pub message: String,
}

/// Routes withheld now, with why.
pub(crate) type Withheld = Vec<(RouteEntry, String)>;

/// The static routes' checks (`ext::<StaticChecks>`).
#[derive(Debug, Default)]
pub struct StaticChecks {
    pub health: BTreeMap<Target, Health>,
    /// Targets down now: [`Session::effective`] does nothing while 0.
    pub down: usize,
    /// Bumped on every change `ip.route.list` shows (its cache key).
    pub generation: u64,
    pub history: VecDeque<CheckEvent>,
    /// The checks run (a daemon with the `route-check` service): without
    /// one, `ip.route.list` says "not checked".
    pub running: bool,
    /// Gateways of the targets down now: [`StaticChecks::withholds`]
    /// rejects every other route with one hash lookup, no allocation.
    down_gateways: HashSet<IpAddr>,
    /// The config generation and clock (ms) of the last sync.
    synced: Option<(u64, u64)>,
    /// The probes' interval when the daemon runs another than RouterOS'
    /// 10 s (`--route-check-interval`, tests).
    pub interval_ms: Option<u64>,
}

impl StaticChecks {
    fn recount(&mut self) {
        self.down_gateways = self.health.iter().filter(|(_, h)| h.down).map(|(t, _)| t.gateway).collect();
        self.down = self.health.values().filter(|h| h.down).count();
        self.generation = self.generation.wrapping_add(1);
    }

    /// Whether route `r` waits for its gateway.
    pub fn withholds(&self, r: &RouteEntry) -> bool {
        self.down > 0
            && r.check_gateway != CheckGateway::None
            && r.gateway.address().is_some_and(|g| self.down_gateways.contains(&g))
            && target_of(r)
                .and_then(|t| self.health.get(&t))
                .is_some_and(|h| h.down)
    }
}

/// The interface of `cfg` whose address reaches `gw` on `link`, as the
/// ARP sender address.
fn arp_source(cfg: &Config, link: &IfName, gw: Ipv4Addr) -> Ipv4Addr {
    let mut first = None;
    for a in cfg.ip.addresses.iter().filter(|a| !a.disabled && a.interface == *link) {
        if let ipnet::IpNet::V4(n) = a.address {
            if n.contains(&gw) {
                return n.addr();
            }
            first.get_or_insert(n.addr());
        }
    }
    first.unwrap_or(Ipv4Addr::UNSPECIFIED)
}

/// How to probe `t` (a route `r` of `cfg` that has it).
fn probe_of(cfg: &Config, t: &Target, r: &RouteEntry) -> ProbeHow {
    match t.method {
        CheckGateway::Ping => {
            let device = t.interface.as_ref().map(|i| i.to_string()).or_else(|| match &t.table {
                RoutingTable::Main => None,
                RoutingTable::Vrf(name) => Some(name.to_string()),
            });
            ProbeHow::Ping { device }
        }
        CheckGateway::Arp => {
            let IpAddr::V4(gw) = t.gateway else {
                return ProbeHow::Unreachable("ARP needs an IPv4 gateway".into());
            };
            match route::reach(cfg, r) {
                Reach::Active { link, .. } => ProbeHow::Arp {
                    src: arp_source(cfg, &link, gw),
                    link,
                },
                Reach::Inactive(why) | Reach::Invalid { why, .. } => {
                    ProbeHow::Unreachable(why.text)
                }
                // Refused by validation (a route without gateway has nothing
                // to check); a hand-edited file still says why.
                Reach::Discard(d) => {
                    ProbeHow::Unreachable(format!("a {} route has no gateway", d.as_str()))
                }
            }
        }
        CheckGateway::Bfd | CheckGateway::None => ProbeHow::Unreachable(String::new()),
    }
}

/// When each target is probed (the `route-check` thread's; no I/O, no
/// clock of its own: `now` is whatever monotonic ms the caller has).
///
/// New targets are spread over the interval by a hash of the target, so
/// a thousand gateways are not probed in one burst every 10 s.
#[derive(Debug)]
pub struct Schedule {
    pub interval_ms: u64,
    pub wait_ms: u64,
    slots: HashMap<Target, Slot>,
    /// Ping sequence number → target of the probe waiting for it.
    by_seq: HashMap<u16, Target>,
    seq: u16,
    /// How late the probes left (ms), for the bench and the service's health.
    pub late_ms_max: u64,
    pub late_ms_sum: u64,
    pub sent: u64,
}

#[derive(Debug)]
struct Slot {
    how: ProbeHow,
    next_at: u64,
    /// The probe waiting for its answer: when it left and its sequence.
    sent: Option<(u64, u16)>,
}

/// A probe to send now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Due {
    pub target: Target,
    pub how: ProbeHow,
    pub seq: u16,
}

impl Default for Schedule {
    fn default() -> Self {
        Self::new(CHECK_INTERVAL_MS, CHECK_WAIT_MS)
    }
}

fn spread(t: &Target, interval: u64) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    t.hash(&mut h);
    h.finish() % interval.max(1)
}

impl Schedule {
    pub fn new(interval_ms: u64, wait_ms: u64) -> Self {
        Self {
            interval_ms: interval_ms.max(1),
            wait_ms: wait_ms.min(interval_ms).max(1),
            slots: HashMap::new(),
            by_seq: HashMap::new(),
            seq: 0,
            late_ms_max: 0,
            late_ms_sum: 0,
            sent: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }

    /// Follow the targets the engine wants now.
    pub fn sync(&mut self, wanted: Vec<ProbeTarget>, now: u64) {
        let mut keep: HashMap<Target, ProbeHow> =
            wanted.into_iter().map(|p| (p.target, p.how)).collect();
        self.slots.retain(|t, slot| match keep.remove(t) {
            Some(how) => {
                slot.how = how;
                true
            }
            None => false,
        });
        let slots = &self.slots;
        self.by_seq.retain(|_, t| slots.contains_key(t));
        for (target, how) in keep {
            let next_at = now.saturating_add(spread(&target, self.interval_ms));
            self.slots.insert(
                target,
                Slot {
                    how,
                    next_at,
                    sent: None,
                },
            );
        }
    }

    /// The probes due at `now`, marked sent.
    pub fn due(&mut self, now: u64) -> Vec<Due> {
        let mut out = Vec::new();
        for (t, slot) in &mut self.slots {
            if slot.sent.is_some() || now < slot.next_at {
                continue;
            }
            let late = now.saturating_sub(slot.next_at);
            self.late_ms_max = self.late_ms_max.max(late);
            self.late_ms_sum = self.late_ms_sum.saturating_add(late);
            self.sent = self.sent.saturating_add(1);
            // Late ticks do not pile up: the next one keeps the period.
            slot.next_at = slot.next_at.saturating_add(self.interval_ms);
            if slot.next_at <= now {
                slot.next_at = now.saturating_add(self.interval_ms);
            }
            self.seq = self.seq.wrapping_add(1);
            slot.sent = Some((now, self.seq));
            if matches!(slot.how, ProbeHow::Ping { .. }) {
                self.by_seq.insert(self.seq, t.clone());
            }
            out.push(Due {
                target: t.clone(),
                how: slot.how.clone(),
                seq: self.seq,
            });
        }
        out
    }

    /// An echo reply from `from` with `seq`: the target it answers.
    pub fn echo(&mut self, from: IpAddr, seq: u16) -> Option<Target> {
        let t = self.by_seq.get(&seq).filter(|t| t.gateway == from)?.clone();
        self.by_seq.remove(&seq);
        let slot = self.slots.get_mut(&t)?;
        slot.sent.take().filter(|(_, s)| *s == seq)?;
        Some(t)
    }

    /// An ARP reply from `from` on `link`: the targets it answers.
    pub fn arp(&mut self, link: &IfName, from: Ipv4Addr) -> Vec<Target> {
        let mut out = Vec::new();
        for (t, slot) in &mut self.slots {
            if slot.sent.is_some()
                && t.gateway == IpAddr::V4(from)
                && matches!(&slot.how, ProbeHow::Arp { link: l, .. } if l == link)
            {
                slot.sent = None;
                out.push(t.clone());
            }
        }
        out
    }

    /// A probe that could not leave (`Unreachable`, send error): a miss
    /// now rather than after the wait.
    pub fn lost(&mut self, t: &Target) {
        if let Some((_, seq)) = self.slots.get_mut(t).and_then(|s| s.sent.take()) {
            self.by_seq.remove(&seq);
        }
    }

    /// Probes that waited `wait_ms` in vain: misses.
    pub fn expired(&mut self, now: u64) -> Vec<Target> {
        let wait = self.wait_ms;
        let mut out = Vec::new();
        for (t, slot) in &mut self.slots {
            if let Some((at, seq)) = slot.sent
                && now.saturating_sub(at) >= wait
            {
                slot.sent = None;
                self.by_seq.remove(&seq);
                out.push(t.clone());
            }
        }
        out
    }

    /// When the next probe is due or times out (ms), to sleep until then.
    pub fn next_event(&self) -> Option<u64> {
        self.slots
            .values()
            .map(|s| match s.sent {
                Some((at, _)) => at.saturating_add(self.wait_ms),
                None => s.next_at,
            })
            .min()
    }
}

impl Session {
    /// The interval the `route-check` thread probes at (shown in
    /// `ip.route.list`; [`CHECK_INTERVAL_MS`] unless the daemon was told
    /// otherwise).
    pub fn route_check_interval(&mut self, ms: u64) {
        if let Some(c) = self.checks_mut() {
            c.interval_ms = Some(ms);
        }
    }

    /// An ICMP prober for the `route-check` thread (used without the lock).
    pub fn route_check_prober(&self) -> Result<corerouter_hal::probe::SharedProber, String> {
        self.hal().prober()
    }

    /// An ARP pinger on `link` for the `route-check` thread.
    pub fn route_check_arp(
        &mut self,
        link: &IfName,
    ) -> Result<Box<dyn corerouter_hal::neigh::ArpPinger>, corerouter_hal::HalError> {
        self.hal_mut().arp_pinger(link)
    }

    /// The static routes' checks, created on first use.
    fn checks_mut(&mut self) -> Option<&mut StaticChecks> {
        self.ext_mut::<StaticChecks>()
    }

    /// Whether static route `r` is withheld now (its gateway is down).
    pub(crate) fn static_withholds(&self, r: &RouteEntry) -> bool {
        self.ext::<StaticChecks>().is_some_and(|c| c.withholds(r))
    }

    /// No static route is withheld: [`Session::effective`] may skip them.
    pub(crate) fn static_checks_quiet(&self) -> bool {
        self.ext::<StaticChecks>().is_none_or(|c| c.down == 0)
    }

    /// The generation of what `ip.route.list` shows of the checks.
    pub(crate) fn static_checks_generation(&self) -> u64 {
        self.ext::<StaticChecks>().map_or(0, |c| c.generation)
    }

    /// The probes the `route-check` thread runs, taken from the running
    /// config (and its DHCP addresses); targets that no route wants any
    /// more are dropped (their routes come back), new ones start
    /// "checking". BFD targets are followed here, from `BfdState`.
    pub fn route_check_targets(&mut self, now_ms: Option<u64>) -> Vec<ProbeTarget> {
        let now = now_ms.or(self.dhcp.now_ms).unwrap_or(0);
        let generation = self.store().generation();
        let running = self.store().running().clone();
        let cfg = self.effective(&running).into_owned();
        let mut wanted: BTreeMap<Target, ProbeHow> = BTreeMap::new();
        for r in running.ip.routes.iter() {
            let Some(t) = target_of(r) else { continue };
            if wanted.len() >= MAX_TARGETS {
                break;
            }
            if let std::collections::btree_map::Entry::Vacant(e) = wanted.entry(t) {
                let how = probe_of(&cfg, e.key(), r);
                e.insert(how);
            }
        }
        let gone: Vec<Target> = self
            .ext::<StaticChecks>()
            .map(|c| c.health.keys().filter(|t| !wanted.contains_key(*t)).cloned().collect())
            .unwrap_or_default();
        let fresh = self
            .ext::<StaticChecks>()
            .is_none_or(|c| wanted.keys().any(|t| !c.health.contains_key(t)));
        if !gone.is_empty() || fresh {
            let was_down = gone.iter().any(|t| {
                self.ext::<StaticChecks>()
                    .and_then(|c| c.health.get(t))
                    .is_some_and(|h| h.down)
            });
            let change = |c: &mut StaticChecks| {
                for t in &gone {
                    c.health.remove(t);
                }
                for t in wanted.keys() {
                    c.health.entry(t.clone()).or_insert_with(|| Health {
                        since: now,
                        ..Health::default()
                    });
                }
                c.recount();
            };
            if was_down {
                self.checks_change(change);
            } else if let Some(c) = self.checks_mut() {
                change(c);
            }
        }
        if let Some(c) = self.checks_mut() {
            c.running = true;
            c.synced = Some((generation, now));
        }
        self.route_check_bfd(now_ms);
        wanted
            .into_iter()
            .filter(|(t, _)| t.method != CheckGateway::Bfd)
            .map(|(target, how)| ProbeTarget { target, how })
            .collect()
    }

    /// The `route-check` thread's sync, once a second: the targets again
    /// only when the config changed (or every [`RESYNC_MS`]), `None` when
    /// the thread's are still right; BFD targets are followed either way.
    /// Unchanged, it costs no pass over the routes under the lock.
    pub fn route_check_sync(&mut self, now_ms: Option<u64>) -> Option<Vec<ProbeTarget>> {
        let now = now_ms.or(self.dhcp.now_ms).unwrap_or(0);
        let generation = self.store().generation();
        let fresh = self.ext::<StaticChecks>().and_then(|c| c.synced).is_some_and(|(g, at)| {
            g == generation && now.saturating_sub(at) < RESYNC_MS
        });
        if fresh {
            self.route_check_bfd(now_ms);
            return None;
        }
        Some(self.route_check_targets(now_ms))
    }

    /// BFD targets: up while their session is up (and not dampened), down
    /// as soon as it is not; no session published yet: still checking.
    fn route_check_bfd(&mut self, now_ms: Option<u64>) {
        let Some(c) = self.ext::<StaticChecks>() else { return };
        let bfd: Vec<Target> =
            c.health.keys().filter(|t| t.method == CheckGateway::Bfd).cloned().collect();
        if bfd.is_empty() {
            return;
        }
        let now = now_ms.or(self.dhcp.now_ms).unwrap_or(0);
        let states: Vec<(Target, bool)> = {
            let st = self.ext::<BfdState>();
            bfd.into_iter()
                .filter_map(|t| {
                    let up = st
                        .and_then(|st| {
                            st.sessions.iter().find(|s| {
                                s.peer == Some(t.gateway) && !s.multihop && s.local.is_none()
                            })
                        })
                        .is_some_and(|s| s.state == "up" && !s.dampened);
                    (up || self.bfd_settled(&t, now)).then_some((t, up))
                })
                .collect()
        };
        // Report only what changes something (no history line per second).
        let changes: Vec<(Target, bool)> = states
            .into_iter()
            .filter(|(t, up)| {
                self.ext::<StaticChecks>()
                    .and_then(|c| c.health.get(t))
                    .is_some_and(|h| !h.known || h.down == *up)
            })
            .collect();
        if !changes.is_empty() {
            self.route_check_report(&changes, Some(now));
        }
    }

    /// Whether a BFD target that is not up counts as down: it was up (or
    /// decided) before, or its session had [`BFD_GRACE_MS`] to come up.
    fn bfd_settled(&self, t: &Target, now: u64) -> bool {
        self.ext::<StaticChecks>()
            .and_then(|c| c.health.get(t))
            .is_some_and(|h| h.known || now.saturating_sub(h.since) >= BFD_GRACE_MS)
    }

    /// A BFD session changed state for its clients (G3.6g; the `bfd`
    /// service calls it with the change, so a route follows at once).
    pub fn route_check_bfd_event(&mut self, peer: IpAddr, multihop: bool, local: Option<IpAddr>, up: bool) {
        if multihop || local.is_some() {
            return;
        }
        let Some(c) = self.ext::<StaticChecks>() else { return };
        let now = self.dhcp.now_ms.unwrap_or(0);
        let hits: Vec<(Target, bool)> = c
            .health
            .keys()
            .filter(|t| t.method == CheckGateway::Bfd && t.gateway == peer)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .filter(|t| up || self.bfd_settled(t, now))
            .map(|t| (t, up))
            .collect();
        if !hits.is_empty() {
            self.route_check_report(&hits, None);
        }
    }

    /// What the probes found (`true`: answered), at `now_ms` (`None`: the
    /// session's clock). Targets that go down or up move their routes in
    /// the data plane in one change, logged and kept in the history.
    pub fn route_check_report(&mut self, results: &[(Target, bool)], now_ms: Option<u64>) {
        let now = now_ms.or(self.dhcp.now_ms).unwrap_or(0);
        let Some(c) = self.ext::<StaticChecks>() else { return };
        let mut next: Vec<(Target, Health)> = Vec::new();
        let mut moved: Vec<(Target, bool, u32)> = Vec::new();
        let mut visible = false;
        for (t, answered) in results {
            let Some(old) = c.health.get(t) else { continue };
            let mut h = old.clone();
            let flips = if *answered {
                h.answered(now)
            } else if t.method == CheckGateway::Bfd {
                h.failed(now)
            } else {
                h.missed(now)
            };
            if flips {
                moved.push((t.clone(), h.down, h.misses));
            }
            visible |= h.known != old.known
                || h.misses != old.misses
                || h.down != old.down
                || h.up_since.is_some() != old.up_since.is_some();
            next.push((t.clone(), h));
        }
        let apply = |c: &mut StaticChecks| {
            for (t, h) in next {
                c.health.insert(t, h);
            }
            if visible {
                c.recount();
            }
        };
        if moved.is_empty() {
            if let Some(c) = self.checks_mut() {
                apply(c);
            }
            return;
        }
        self.checks_change(apply);
        let running = self.store().running().clone();
        let time = self.now();
        // Routes per moved target, in one pass over the routes.
        let mut counts: HashMap<Target, usize> = moved.iter().map(|(t, _, _)| (t.clone(), 0)).collect();
        let gateways: HashSet<IpAddr> = moved.iter().map(|(t, _, _)| t.gateway).collect();
        for r in running.ip.routes.iter() {
            if r.gateway.address().is_some_and(|g| gateways.contains(&g))
                && let Some(n) = target_of(r).and_then(|t| counts.get_mut(&t))
            {
                *n += 1;
            }
        }
        let total = moved.len();
        let downs = moved.iter().filter(|(_, d, _)| *d).count();
        if total > MAX_LOG_LINES {
            let message = format!(
                "check-gateway: {downs} gateway(s) down and {} up at once; the first {MAX_LOG_LINES} follow, \
                 the rest in ip.route.check.history",
                total - downs
            );
            log::warn!("{message}");
            self.log_event(&["route", "warning"], crate::logging::DAEMON, message, Value::Null);
        }
        for (i, (t, down, misses)) in moved.into_iter().enumerate() {
            let routes = counts.get(&t).copied().unwrap_or(0);
            let logged = i < MAX_LOG_LINES;
            let how = t.method.as_str();
            let gw = t.text();
            let message = if down {
                match t.method {
                    CheckGateway::Bfd => format!(
                        "gateway {gw}: BFD session down: {routes} route(s) inactive"
                    ),
                    _ => format!(
                        "gateway {gw} did not answer {misses} {how} checks: {routes} route(s) inactive"
                    ),
                }
            } else {
                format!("gateway {gw} answers {how} again: {routes} route(s) back")
            };
            let level = if down { "warning" } else { "info" };
            if logged {
                log::log!(
                    if down { log::Level::Warn } else { log::Level::Info },
                    "check-gateway: {message}"
                );
                self.log_event(
                    &["route", level],
                    crate::logging::DAEMON,
                    message.clone(),
                    json!({"gateway": gw, "method": how, "state": if down { "down" } else { "up" }}),
                );
            }
            if let Some(c) = self.checks_mut() {
                c.history.push_back(CheckEvent {
                    time,
                    target: t,
                    to: if down { "down" } else { "up" },
                    routes,
                    message,
                });
                while c.history.len() > MAX_HISTORY {
                    c.history.pop_front();
                }
            }
        }
    }

    /// Change the checks with `f` and push what it changes in the data
    /// plane (routes that leave or come back), in one apply.
    fn checks_change(&mut self, f: impl FnOnce(&mut StaticChecks)) {
        let running = self.store().running().clone();
        let before = self.effective(&running).into_owned();
        let Some(c) = self.checks_mut() else { return };
        f(c);
        let after = self.effective(&running).into_owned();
        if before != after
            && let Err(e) = self.hal_mut().apply(&before, &after)
        {
            log::warn!("check-gateway: routes not applied: {e}");
        }
    }

    /// The check of every static route of `cfg` that has one, by route id,
    /// and the routes withheld now with why (for `ip.route.list`).
    pub(crate) fn static_route_checks(
        &self,
        cfg: &Config,
    ) -> (Vec<(ItemId, RouteCheck)>, Withheld) {
        let mut checks = Vec::new();
        let mut withheld = Vec::new();
        let c = self.ext::<StaticChecks>();
        let running = c.is_some_and(|c| c.running);
        let interval = c.and_then(|c| c.interval_ms).unwrap_or(CHECK_INTERVAL_MS);
        let now = self.dhcp.now_ms.unwrap_or(0);
        for r in cfg.ip.routes.iter() {
            let Some(t) = target_of(r) else { continue };
            let h = c.and_then(|c| c.health.get(&t));
            let mut check = route_check(&t, h, running, now);
            if t.method != CheckGateway::Bfd {
                check.interval_secs = interval.div_ceil(1000);
            }
            if h.is_some_and(|h| h.down) {
                let why = match t.method {
                    CheckGateway::Bfd => format!("BFD session to gateway {} is down", t.text()),
                    m => format!("gateway {} does not answer check-gateway={m}", t.text()),
                };
                withheld.push((r.clone(), why));
            }
            checks.push((r.id, check));
        }
        (checks, withheld)
    }

    /// `ip.route.check.list`: one row per target.
    pub fn route_check_rows(&self) -> Vec<Value> {
        let Some(c) = self.ext::<StaticChecks>() else { return Vec::new() };
        let running = self.store().running();
        let mut routes: HashMap<&Target, usize> = HashMap::new();
        let targets: Vec<(Target, ItemId)> =
            running.ip.routes.iter().filter_map(|r| Some((target_of(r)?, r.id))).collect();
        for (t, _) in &targets {
            *routes.entry(t).or_default() += 1;
        }
        let now = self.dhcp.now_ms.unwrap_or(0);
        c.health
            .iter()
            .map(|(t, h)| {
                json!({
                    "gateway": t.text(),
                    "method": t.method.as_str(),
                    "routing_table": t.table.to_string(),
                    "bfd_profile": (t.method == CheckGateway::Bfd).then_some(&t.profile),
                    "routes": routes.get(t).copied().unwrap_or(0),
                    "status": h.status(),
                    "misses": h.misses,
                    "down_secs": h.down_since.map(|d| now.saturating_sub(d) / 1000),
                    "hold_down_secs": h.hold_left_ms(now).map(|ms| ms.div_ceil(1000)),
                    "flaps_15m": h.flaps(now),
                })
            })
            .collect()
    }

    /// `ip.route.check.history`, newest last; `gateway`: only that one's.
    pub fn route_check_history(&self, gateway: Option<IpAddr>) -> Vec<Value> {
        let Some(c) = self.ext::<StaticChecks>() else { return Vec::new() };
        c.history
            .iter()
            .filter(|e| gateway.is_none_or(|g| g == e.target.gateway))
            .map(|e| {
                json!({
                    "time": e.time,
                    "gateway": e.target.text(),
                    "method": e.target.method.as_str(),
                    "to": e.to,
                    "routes": e.routes,
                    "message": e.message,
                })
            })
            .collect()
    }
}

/// What `ip.route.list` shows of the check of a route with target `t`.
fn route_check(t: &Target, h: Option<&Health>, running: bool, now: u64) -> RouteCheck {
    let interval_secs = match t.method {
        CheckGateway::Bfd => 0,
        _ => CHECK_INTERVAL_MS / 1000,
    };
    let status = match h {
        Some(h) => h.status(),
        None if running => "checking",
        None => "not-checked",
    };
    RouteCheck {
        method: t.method.as_str(),
        interval_secs,
        misses: h.map_or(0, |h| h.misses),
        down: h.is_some_and(|h| h.down),
        down_since_ms: h.and_then(|h| h.down_since),
        status: if running { status } else { "not-checked" },
        hold_secs: h.and_then(|h| h.hold_left_ms(now)).map(|ms| ms.div_ceil(1000)),
        profile: (t.method == CheckGateway::Bfd).then(|| t.profile.clone()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn down_after_two_misses_up_at_first_answer() {
        let mut h = Health::default();
        assert_eq!(h.status(), "checking");
        assert!(!h.missed(0));
        assert!(h.missed(10_000));
        assert_eq!((h.status(), h.down_since), ("unreachable", Some(10_000)));
        // RouterOS: the first down comes back at the first answer.
        assert!(h.answered(20_000));
        assert_eq!(h.status(), "reachable");
    }

    #[test]
    fn flapping_holds_the_routes_down_longer_each_time() {
        let mut h = Health::default();
        let mut t = 0;
        let down = |h: &mut Health, t: &mut u64| {
            h.missed(*t);
            *t += 10_000;
            assert!(h.missed(*t));
            *t += 10_000;
        };
        down(&mut h, &mut t);
        assert!(h.answered(t));
        t += 10_000;
        down(&mut h, &mut t);
        // Second down in the window: 10 s of answers before coming back.
        assert_eq!(h.hold_ms(t), HOLD_BASE_MS);
        assert!(!h.answered(t));
        assert_eq!(h.hold_left_ms(t), Some(HOLD_BASE_MS));
        // A miss meanwhile starts the hold again.
        assert!(!h.missed(t + 5_000));
        assert!(!h.answered(t + 10_000));
        assert!(h.answered(t + 20_000));
        t += 30_000;
        down(&mut h, &mut t);
        assert_eq!(h.hold_ms(t), 2 * HOLD_BASE_MS);
        // Fifteen quiet minutes forget the flaps.
        assert_eq!(h.hold_ms(t + FLAP_WINDOW_MS + 60_000), 0);
    }

    #[test]
    fn the_hold_down_is_capped() {
        let mut h = Health::default();
        for i in 0..MAX_DOWNS as u64 + 4 {
            h.misses = 1;
            h.fail_after(i, 1);
            h.down = false;
        }
        assert_eq!(h.hold_ms(100), HOLD_MAX_MS);
        assert!(h.downs.len() <= MAX_DOWNS);
    }

    fn t(gw: &str, method: CheckGateway) -> Target {
        Target {
            method,
            gateway: gw.parse().unwrap(),
            interface: None,
            table: RoutingTable::Main,
            profile: String::new(),
        }
    }

    #[test]
    fn the_schedule_spreads_probes_and_keeps_the_period() {
        let mut s = Schedule::new(10_000, 2_000);
        let wanted: Vec<ProbeTarget> = (0..1000u32)
            .map(|i| ProbeTarget {
                target: t(&Ipv4Addr::from(0x0a00_0000 + i).to_string(), CheckGateway::Ping),
                how: ProbeHow::Ping { device: None },
            })
            .collect();
        s.sync(wanted, 0);
        // Spread: no 100 ms slice of the interval carries a burst.
        let mut per_slice = [0u32; 100];
        let mut now = 0;
        while now < 10_000 {
            for d in s.due(now) {
                per_slice[(now / 100) as usize] += 1;
                assert_eq!(s.echo(d.target.gateway, d.seq), Some(d.target));
            }
            now += 1;
        }
        assert_eq!(per_slice.iter().sum::<u32>(), 1000);
        assert!(per_slice.iter().all(|n| *n < 40), "{per_slice:?}");
        // Every target again in the next interval, none twice.
        let mut again = 0;
        while now < 20_000 {
            again += s.due(now).len();
            now += 1;
        }
        assert_eq!(again, 1000);
        assert_eq!(s.late_ms_max, 0);
    }

    #[test]
    fn unanswered_probes_expire_and_wrong_answers_do_not_count() {
        let mut s = Schedule::new(10_000, 2_000);
        let a = t("10.0.0.1", CheckGateway::Ping);
        let b = t("10.0.1.1", CheckGateway::Arp);
        s.sync(
            vec![
                ProbeTarget { target: a.clone(), how: ProbeHow::Ping { device: None } },
                ProbeTarget {
                    target: b.clone(),
                    how: ProbeHow::Arp { link: "ether2".parse().unwrap(), src: Ipv4Addr::UNSPECIFIED },
                },
            ],
            0,
        );
        let due = s.due(10_000);
        assert_eq!(due.len(), 2);
        let seq = due.iter().find(|d| d.target == a).unwrap().seq;
        // Another host's echo, or the right host with a stale sequence.
        assert_eq!(s.echo("10.0.0.9".parse().unwrap(), seq), None);
        assert_eq!(s.echo(a.gateway, seq.wrapping_add(7)), None);
        // ARP from the gateway, but on the wrong link.
        assert!(s.arp(&"ether1".parse().unwrap(), "10.0.1.1".parse().unwrap()).is_empty());
        assert_eq!(s.arp(&"ether2".parse().unwrap(), "10.0.1.1".parse().unwrap()), vec![b]);
        assert_eq!(s.expired(11_000), Vec::<Target>::new());
        assert_eq!(s.expired(12_000), vec![a.clone()]);
        // Dropped targets leave no waiting sequence behind.
        s.sync(Vec::new(), 12_000);
        assert!(s.is_empty() && s.by_seq.is_empty());
    }
}

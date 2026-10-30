//! G1.3e: the restored config reaches the data plane in stages when the
//! whole of it is refused at boot, so a firewall rule, a route or an MPLS
//! entry the kernel will not take never keeps the management address down.
//!
//! - First the whole config, in one `apply` (the normal case: nothing more).
//! - Refused: the core (interfaces, addresses and whatever no section below
//!   takes), then each section on top of what is applied, in the order the
//!   data plane needs them. A refused section stays out, with its reason, in
//!   the log, the health checks, `state.inspect` and `auth.whoami` (every
//!   client warns).
//! - G1.3g: a refused firewall loses only the rule the kernel refuses,
//!   found by checks that load nothing ([`Hal::check_firewall`], as
//!   `nft --check`): the first refused rule out, check again, until the
//!   rest would load; a backend whose refusal names no rule is bisected
//!   the same way (still checks only). The reduced firewall goes in once,
//!   and only if it keeps every management connection the full one lets
//!   through (the commit's lockout probes, [`crate::lockout`]): else the
//!   whole firewall stays out, saying which rule and why. The rule shows
//!   `invalid` (flag I) with the kernel's reason.
//! - Retried with backoff (1, 2, 4… 60 s), not every second; the log says it
//!   again every 10 minutes while something is still out.
//! - A commit starts from what the data plane holds. A refused section the
//!   commit does not touch stays out of both sides (as an absent port does,
//!   G1.3b); one it touches goes in, all or nothing like any commit. Safe
//!   Mode and transactions do not change: partial only at boot and on retry.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use corerouter_hal::{Hal, HalError, RefusedRule};
use corerouter_model::ItemId;
use corerouter_model::config::Config;
use corerouter_model::firewall::Table;
use serde::Serialize;

use crate::Session;
use crate::lockout::{Link, firewall_cut};

/// What the boot must keep reachable (G1.3g), from whoever starts the
/// session: the daemon knows its ports before it opens them, and the
/// boot comes first.
#[derive(Debug, Clone, Default)]
pub struct BootEnv {
    /// TCP ports management connects to (control channel, TLS,
    /// WebSocket). The web's come from the config.
    pub management_ports: Vec<u16>,
}

/// One part of the config the boot can leave out.
pub(crate) struct Section {
    pub name: &'static str,
    /// Copy this section from `src` into `dst`.
    take: fn(&mut Config, &Config),
    /// The section is the same in both.
    same: fn(&Config, &Config) -> bool,
}

/// What a commit or a retry could not apply because the core itself was
/// refused (nothing of the config is in the data plane).
pub(crate) const CORE: &str = "core";

/// In apply order: routes need the addresses; the firewall and the rest
/// name interfaces; MPLS last, as `hal-linux` does.
pub(crate) const SECTIONS: &[Section] = &[
    Section {
        name: "ethernet",
        take: |dst, src| {
            for (name, iface) in dst.interfaces.iter_mut() {
                iface.ethernet = src
                    .interfaces
                    .get(name)
                    .map(|i| i.ethernet.clone())
                    .unwrap_or_default();
            }
        },
        same: |a, b| {
            a.interfaces.len() == b.interfaces.len()
                && a.interfaces
                    .iter()
                    .zip(b.interfaces.iter())
                    .all(|((n, x), (m, y))| n == m && x.ethernet == y.ethernet)
        },
    },
    Section {
        name: "routes",
        take: |dst, src| dst.ip.routes = src.ip.routes.clone(),
        same: |a, b| a.ip.routes == b.ip.routes,
    },
    Section {
        name: "firewall",
        take: |dst, src| {
            dst.ip.firewall = src.ip.firewall.clone();
            dst.ip.subscriber_notice = src.ip.subscriber_notice.clone();
            dst.interface_lists = src.interface_lists.clone();
        },
        same: |a, b| {
            a.ip.firewall == b.ip.firewall
                && a.ip.subscriber_notice == b.ip.subscriber_notice
                && a.interface_lists == b.interface_lists
        },
    },
    Section {
        name: "cgnat",
        take: |dst, src| dst.ip.cgnat = src.ip.cgnat.clone(),
        same: |a, b| a.ip.cgnat == b.ip.cgnat,
    },
    Section {
        name: "fastpath",
        take: |dst, src| dst.ip.fastpath = src.ip.fastpath.clone(),
        same: |a, b| a.ip.fastpath == b.ip.fastpath,
    },
    Section {
        name: "tuning",
        take: |dst, src| dst.system.tuning = src.system.tuning.clone(),
        same: |a, b| a.system.tuning == b.system.tuning,
    },
    Section {
        name: "xdp",
        take: |dst, src| dst.ip.xdp = src.ip.xdp.clone(),
        same: |a, b| a.ip.xdp == b.ip.xdp,
    },
    Section {
        name: "arp",
        take: |dst, src| dst.ip.arp = src.ip.arp.clone(),
        same: |a, b| a.ip.arp == b.ip.arp,
    },
    Section {
        name: "mpls",
        take: |dst, src| dst.routing.mpls = src.routing.mpls.clone(),
        same: |a, b| a.routing.mpls == b.routing.mpls,
    },
];

fn section(name: &str) -> Option<&'static Section> {
    SECTIONS.iter().find(|s| s.name == name)
}

/// A part of the config that did not reach the data plane, and why.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BootFailure {
    pub section: &'static str,
    /// G1.3g: only this rule of the section is out (the rest is in).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<ItemId>,
    pub error: String,
}

impl BootFailure {
    fn whole(section: &'static str, error: String) -> Self {
        Self {
            section,
            rule: None,
            error,
        }
    }

    /// `firewall`, or `firewall *5` for one rule.
    pub fn label(&self) -> String {
        match self.rule {
            Some(id) => format!("{} {id}", self.section),
            None => self.section.to_owned(),
        }
    }
}

/// Most rules the boot leaves out one by one before it leaves the
/// firewall out whole, and most checks it spends finding them.
const MAX_RULES_OUT: usize = 16;
const MAX_CHECKS: usize = 64;

/// What [`isolate_firewall`] found.
enum Isolated {
    /// The firewall without these rules loads and keeps management.
    Rules(Config, Vec<RefusedRule>),
    /// The firewall stays out whole, for this reason.
    Whole(String),
}

/// Every rule of `cfg` that reaches the data plane, in table order.
fn live_rules(cfg: &Config) -> Vec<ItemId> {
    Table::ALL
        .iter()
        .flat_map(|t| cfg.ip.firewall.rules(*t).iter())
        .filter(|r| !r.disabled && !r.section)
        .map(|r| r.id)
        .collect()
}

/// Turn rule `id` off in `cfg`; `false` if no table has it.
fn disable_rule(cfg: &mut Config, id: ItemId) -> bool {
    Table::ALL.iter().any(|t| {
        cfg.ip
            .firewall
            .rules_mut(*t)
            .find_mut(|r| r.id == id)
            .map(|r| r.disabled = true)
            .is_some()
    })
}

/// The check of `cfg`: `Some(true)` refused, `Some(false)` loads, `None`
/// the backend cannot say.
fn refused(hal: &mut dyn Hal, cfg: &Config, checks: &mut usize) -> Option<bool> {
    *checks += 1;
    match hal.check_firewall(cfg) {
        Ok(v) => Some(!v.is_empty()),
        Err(HalError::Rejected(_)) => Some(true),
        Err(_) => None,
    }
}

/// The rule that makes `cfg`'s firewall refused when the backend does not
/// name it: the shortest refused prefix of the rules (in table order),
/// by halving, checks only (~log₂ n). `None`: refused with no rule at
/// all, or the backend stopped answering.
fn bisect(hal: &mut dyn Hal, cfg: &Config, checks: &mut usize) -> Option<ItemId> {
    let rules = live_rules(cfg);
    let prefix = |k: usize| {
        let mut c = cfg.clone();
        for id in rules.get(k..).unwrap_or(&[]) {
            disable_rule(&mut c, *id);
        }
        c
    };
    if refused(hal, &prefix(0), checks)? {
        return None;
    }
    // prefix(lo) loads, prefix(hi) is refused (the whole is).
    let (mut lo, mut hi) = (0, rules.len());
    while hi - lo > 1 {
        if *checks >= MAX_CHECKS {
            return None;
        }
        let mid = lo + (hi - lo) / 2;
        if refused(hal, &prefix(mid), checks)? {
            hi = mid;
        } else {
            lo = mid;
        }
    }
    rules.get(hi.checked_sub(1)?).copied()
}

/// The firewall of `next` the kernel refused (`why`): the rules to leave
/// out so the rest loads, found by checks only, and whether the rest
/// still lets management in.
fn isolate_firewall(hal: &mut dyn Hal, next: &Config, why: &str, env: &BootEnv) -> Isolated {
    let mut out = next.clone();
    let mut left: Vec<RefusedRule> = Vec::new();
    let mut checks = 0usize;
    loop {
        if checks >= MAX_CHECKS || left.len() >= MAX_RULES_OUT {
            return Isolated::Whole(format!(
                "{why} (not isolated to at most {MAX_RULES_OUT} rules in {MAX_CHECKS} checks: \
                 the whole firewall stays out)"
            ));
        }
        checks += 1;
        let found = match hal.check_firewall(&out) {
            Ok(v) => match v.into_iter().next() {
                Some(r) => r,
                None => break,
            },
            Err(HalError::Rejected(e)) => match bisect(hal, &out, &mut checks) {
                Some(id) => RefusedRule { id, reason: e },
                None => return Isolated::Whole(why.to_owned()),
            },
            // No check on this backend: as G1.3e, the whole section.
            Err(_) => return Isolated::Whole(why.to_owned()),
        };
        // The same rule again (a backend that names a rule it does not
        // have): no progress.
        if left.iter().any(|r| r.id == found.id) || !disable_rule(&mut out, found.id) {
            return Isolated::Whole(why.to_owned());
        }
        left.push(found);
    }
    // The firewall loads whole: what the kernel refused is not a rule.
    if left.is_empty() {
        return Isolated::Whole(why.to_owned());
    }
    if let Some(cut) = management_cut(next, &out, &left, env) {
        let rules = left
            .iter()
            .map(|r| format!("{} ({})", r.id, r.reason))
            .collect::<Vec<_>>()
            .join(", ");
        return Isolated::Whole(format!(
            "rule {rules} was refused by the kernel and, without it, the firewall would cut \
             management: {cut}; the whole firewall stays out until it is fixed"
        ));
    }
    Isolated::Rules(out, left)
}

/// Most connections the management guard walks (addresses × ports ×
/// sources), and most of each kind.
const MAX_LINKS: usize = 4096;
const MAX_ADDRESSES: usize = 32;
const MAX_SOURCES: usize = 64;

/// The management connection `reduced` drops and `intended` (the firewall
/// as saved) lets in, if any: a new login and an established session
/// (the commit's lockout probes) to every address of the router on every
/// management port, from a host of each of its networks, from outside, and
/// from the sources the refused rules name (their `src-address` and the
/// entries of their `src-address-list`), the ones an `accept` for
/// management usually names.
fn management_cut(
    intended: &Config,
    reduced: &Config,
    left: &[RefusedRule],
    env: &BootEnv,
) -> Option<String> {
    let mut ports = env.management_ports.clone();
    for w in [&reduced.system.web.www_ssl, &reduced.system.web.www] {
        if w.enabled {
            ports.push(w.port);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return None;
    }
    let mut locals: Vec<IpAddr> = vec![IpAddr::V4(Ipv4Addr::LOCALHOST)];
    let mut sources: Vec<IpAddr> = vec![
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
    ];
    for a in reduced.ip.addresses.iter().filter(|a| !a.disabled).take(MAX_ADDRESSES) {
        let me = a.address.addr();
        locals.push(me);
        if let Some(h) = a.address.hosts().find(|h| *h != me) {
            sources.push(h);
        }
    }
    let fw = &intended.ip.firewall;
    for r in left {
        let Some(rule) = Table::ALL
            .iter()
            .find_map(|t| fw.rules(*t).iter().find(|x| x.id == r.id))
        else {
            continue;
        };
        if let Some(src) = &rule.matchers.src_address {
            sources.push(src.value.bounds().0);
        }
        if let Some(list) = &rule.matchers.src_address_list {
            sources.extend(
                fw.address_lists
                    .list()
                    .iter()
                    .filter(|e| !e.disabled && e.list == list.value)
                    .take(16)
                    .map(|e| e.address.bounds().0),
            );
        }
    }
    sources.sort_unstable();
    sources.dedup();
    sources.truncate(MAX_SOURCES);
    let mut walked = 0usize;
    for local in &locals {
        for peer in sources.iter().filter(|p| p.is_ipv4() == local.is_ipv4()) {
            if peer == local && !local.is_loopback() {
                continue;
            }
            for port in &ports {
                walked += 1;
                if walked > MAX_LINKS {
                    return None;
                }
                let link = Link {
                    peer: SocketAddr::new(*peer, 40_000),
                    local: SocketAddr::new(*local, *port),
                };
                if let Some(why) = firewall_cut(intended, reduced, &[], &[], &link) {
                    return Some(why);
                }
            }
        }
    }
    None
}

/// What [`staged`] left in the data plane.
pub(crate) struct Staged {
    pub applied: Config,
    pub failed: Vec<BootFailure>,
}

/// Apply `target` over `base` (what the data plane holds): whole first; if
/// refused, the core, then section by section. The data plane ends holding
/// `applied` (`base` when even the core is refused).
pub(crate) fn staged(hal: &mut dyn Hal, base: &Config, target: &Config, env: &BootEnv) -> Staged {
    // Whole first only from nothing (the boot, or the core still out): on
    // a retry over a partial data plane only what is out is tried, one
    // apply per section.
    let mut first = String::new();
    if *base == Config::default() {
        match hal.apply(base, target) {
            Ok(()) => {
                return Staged {
                    applied: target.clone(),
                    failed: Vec::new(),
                };
            }
            Err(e) => first = e.to_string(),
        }
    }
    let mut applied = target.clone();
    for s in SECTIONS {
        (s.take)(&mut applied, base);
    }
    if applied != *base
        && let Err(e) = hal.apply(base, &applied)
    {
        // The core alone is refused: nothing to stage on top. The whole
        // apply's error says more (it names what the kernel refused).
        return Staged {
            applied: base.clone(),
            failed: vec![BootFailure::whole(
                CORE,
                if first.is_empty() || e.to_string() == first {
                    e.to_string()
                } else {
                    format!("{e} (whole config: {first})")
                },
            )],
        };
    }
    let mut failed = Vec::new();
    for s in SECTIONS {
        if (s.same)(&applied, target) {
            continue;
        }
        let mut next = applied.clone();
        (s.take)(&mut next, target);
        let e = match hal.apply(&applied, &next) {
            Ok(()) => {
                applied = next;
                continue;
            }
            Err(e) => e.to_string(),
        };
        if s.name != FIREWALL {
            failed.push(BootFailure::whole(s.name, e));
            continue;
        }
        // G1.3g: only the rules the kernel refuses stay out.
        match isolate_firewall(hal, &next, &e, env) {
            Isolated::Rules(reduced, rules) => match hal.apply(&applied, &reduced) {
                Ok(()) => {
                    applied = reduced;
                    failed.extend(rules.into_iter().map(|r| BootFailure {
                        section: FIREWALL,
                        rule: Some(r.id),
                        error: r.reason,
                    }));
                }
                Err(back) => failed.push(BootFailure::whole(
                    FIREWALL,
                    format!("{e} (and without the refused rules: {back})"),
                )),
            },
            Isolated::Whole(why) => failed.push(BootFailure::whole(FIREWALL, why)),
        }
    }
    Staged { applied, failed }
}

const FIREWALL: &str = "firewall";

/// Backoff of the retries, seconds.
const RETRY_MAX: u64 = 60;
/// Backoff when only single rules are out (G1.3g): finding them again
/// costs the kernel a validation per rule (10 000 rules: 5.3 s with
/// nftables' lock held, **medido**), and a rule refused at boot is
/// usually refused for good; a commit that changes it tries at once.
const RETRY_RULES_MAX: u64 = 600;
/// The log says again what is still out this often, seconds.
const REMIND: u64 = 600;

/// The boot apply that did not finish: what the data plane holds and what
/// is still out. Absent (default, `failed` empty) once everything is in.
#[derive(Default)]
pub(crate) struct BootApply {
    /// What the data plane holds (the core and the sections that went in).
    applied: Config,
    failed: Vec<BootFailure>,
    /// Next retry (seconds since the epoch); 0: the next tick.
    next_try: u64,
    /// Wait after the next failed retry.
    delay: u64,
    /// When the log last said what is out.
    logged: u64,
}

impl BootApply {
    pub(crate) fn pending(&self) -> bool {
        !self.failed.is_empty()
    }

    pub(crate) fn failed(&self) -> &[BootFailure] {
        &self.failed
    }

    /// The core was refused: nothing of the config is in the data plane.
    fn nothing(&self) -> bool {
        self.failed.iter().any(|f| f.section == CORE)
    }

    /// `cfg` with what is out taken as the data plane has it.
    fn mask(&self, cfg: &Config) -> Config {
        let mut out = cfg.clone();
        for f in &self.failed {
            if let Some(s) = section(f.section) {
                (s.take)(&mut out, &self.applied);
            }
        }
        out
    }
}

/// Rule `id` of `cfg`, in whatever table.
fn rule_of(cfg: &Config, id: ItemId) -> Option<&corerouter_model::FirewallRule> {
    Table::ALL
        .iter()
        .find_map(|t| cfg.ip.firewall.rules(*t).iter().find(|r| r.id == id))
}

/// One line for `storage.boot_apply_error` and the old log lines.
pub(crate) fn summary(failed: &[BootFailure]) -> Option<String> {
    if failed.is_empty() {
        return None;
    }
    Some(
        failed
            .iter()
            .map(|f| format!("{}: {}", f.label(), f.error))
            .collect::<Vec<_>>()
            .join("; "),
    )
}

/// The boot's outcome, logged and kept for the retries.
pub(crate) fn at_boot(hal: &mut dyn Hal, target: &Config, env: &BootEnv) -> BootApply {
    let s = staged(hal, &Config::default(), target, env);
    log_outcome(&s.failed, "restored config");
    BootApply {
        applied: s.applied,
        failed: s.failed,
        next_try: 0,
        delay: 1,
        logged: 0,
    }
}

fn log_outcome(failed: &[BootFailure], what: &str) {
    if failed.is_empty() {
        return;
    }
    if failed.iter().any(|f| f.section == CORE) {
        for f in failed {
            log::error!("{what} not applied (retried with backoff): {}", f.error);
        }
        return;
    }
    for f in failed {
        match f.rule {
            Some(id) => log::error!(
                "{what}: {} rule {id} left out, the rest of the firewall is in \
                 (retried with backoff): {}",
                f.section,
                f.error
            ),
            None => log::error!(
                "{what}: section {} not applied, the rest is (retried with backoff): {}",
                f.section,
                f.error
            ),
        }
    }
}

impl Session {
    /// What the data plane holds of `running` while a boot apply is
    /// pending; `None` once everything is in.
    pub(crate) fn boot_applied(&self) -> Option<&Config> {
        self.ext::<BootApply>()
            .filter(|b| b.pending())
            .map(|b| &b.applied)
    }

    /// Nothing of the config reached the data plane (the core refused).
    pub(crate) fn boot_core_out(&self) -> bool {
        self.ext::<BootApply>().is_some_and(|b| b.pending() && b.nothing())
    }

    /// The firewall rules the boot left out (G1.3g), with the kernel's
    /// reason: `ip.firewall.*.list` shows them invalid (flag I).
    pub(crate) fn boot_refused_rules(&self) -> std::collections::HashMap<ItemId, String> {
        self.ext::<BootApply>()
            .map(|b| {
                b.failed
                    .iter()
                    .filter_map(|f| Some((f.rule?, f.error.clone())))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The parts of the config the boot left out, for the health checks
    /// and `auth.whoami`.
    pub fn boot_failures(&self) -> Vec<BootFailure> {
        self.ext::<BootApply>()
            .map(|b| b.failed.clone())
            .unwrap_or_default()
    }

    /// `to` as the data plane gets it while a boot apply is pending: a
    /// refused section a commit from `running` does not touch stays as the
    /// data plane has it, and a refused rule (G1.3g) the commit leaves as
    /// it was stays out (off), so editing another rule does not fail on it.
    /// With what stays out after the commit. `None`: nothing to mask (no
    /// boot pending, or the core itself is out).
    pub(crate) fn boot_mask(&self, running: &Config, to: &Config) -> Option<(Config, Vec<BootFailure>)> {
        let b = self.ext::<BootApply>().filter(|b| b.pending() && !b.nothing())?;
        let mut out = to.clone();
        let mut kept = Vec::new();
        for f in &b.failed {
            let Some(s) = section(f.section) else {
                continue;
            };
            if (s.same)(running, to) {
                (s.take)(&mut out, &b.applied);
                kept.push(f.clone());
            } else if let Some(id) = f.rule
                && rule_of(running, id).is_some()
                && rule_of(running, id) == rule_of(to, id)
            {
                disable_rule(&mut out, id);
                kept.push(f.clone());
            }
        }
        Some((out, kept))
    }

    /// A commit reached the data plane, which holds `applied` now: of
    /// what the boot left out, only `kept` still is.
    pub(crate) fn boot_committed(&mut self, kept: Vec<BootFailure>, applied: Config) {
        let Some(b) = self.ext_mut::<BootApply>() else {
            return;
        };
        if !b.pending() {
            return;
        }
        b.failed = kept;
        b.applied = applied;
        b.next_try = 0;
        b.delay = 1;
        if b.failed.is_empty() {
            log::info!("the whole config reached the data plane with this commit");
            *b = BootApply::default();
        }
        self.publish_boot();
    }

    /// A change that is not a commit (a DHCP lease, a PPPoE session, a
    /// port that came back…) from `before` to `after`, both computed from
    /// `running`: while a boot apply is pending, what the boot left out
    /// stays out of both sides, as in a commit (G1.3g: a lease used to
    /// carry the refused XDP filter again and be undone). With nothing of
    /// the config in (the core refused), nothing: the retry applies it all.
    pub(crate) fn apply_side(&mut self, before: &Config, after: &Config) -> Result<(), HalError> {
        let masks = match self.ext::<BootApply>().filter(|b| b.pending()) {
            None => None,
            Some(b) if b.nothing() => return Ok(()),
            Some(b) => Some((b.mask(before), b.mask(after))),
        };
        let Some((from, to)) = masks else {
            return self.hal_mut().apply(before, after);
        };
        self.hal_mut().apply(&from, &to)?;
        if let Some(b) = self.ext_mut::<BootApply>() {
            b.applied = to;
        }
        Ok(())
    }

    /// Retry what the boot left out (called by [`Session::tick`]): only
    /// when the backoff says so.
    pub(crate) fn retry_boot_apply(&mut self) {
        let now = self.now().unwrap_or(0);
        let Some(b) = self.ext::<BootApply>() else {
            return;
        };
        if !b.pending() || now < b.next_try {
            return;
        }
        let base = b.applied.clone();
        let before = b.failed.clone();
        let target = self.effective(self.store().running()).into_owned();
        let env = self.ext::<BootEnv>().cloned().unwrap_or_default();
        let tried = crate::guard::run("boot apply", || {
            Ok::<_, crate::EngineError>(staged(self.hal_mut(), &base, &target, &env))
        });
        let Some(b) = self.ext_mut::<BootApply>() else {
            return;
        };
        let s = match tried {
            Ok(s) => s,
            Err(e) => Staged {
                applied: base,
                failed: vec![BootFailure::whole(CORE, e.to_string())],
            },
        };
        b.applied = s.applied;
        if s.failed.is_empty() {
            log::info!("restored config applied on retry: every section is in");
            *b = BootApply::default();
            self.publish_boot();
            return;
        }
        let changed = s.failed != before;
        b.failed = s.failed;
        if changed {
            b.delay = 1;
        }
        let max = if b.failed.iter().all(|f| f.rule.is_some()) {
            RETRY_RULES_MAX
        } else {
            RETRY_MAX
        };
        b.next_try = now.saturating_add(b.delay);
        b.delay = b.delay.saturating_mul(2).min(max);
        if b.logged == 0 {
            // The boot logged it (it has no clock): remind from now on.
            b.logged = now;
        }
        let remind = now.saturating_sub(b.logged) >= REMIND;
        if changed || remind {
            b.logged = now;
            let failed = b.failed.clone();
            log_outcome(&failed, "restored config still");
        }
        self.publish_boot();
    }

    /// `state.inspect` shows what is still out.
    fn publish_boot(&mut self) {
        let failed = self.boot_failures();
        let st = self.storage_status_mut();
        st.boot_apply_error = summary(&failed);
        st.boot_apply_failed = failed;
    }
}

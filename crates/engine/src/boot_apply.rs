//! G1.3e: the restored config reaches the data plane in stages when the
//! whole of it is refused at boot, so a firewall rule, a route or an MPLS
//! entry the kernel will not take never keeps the management address down.
//!
//! - First the whole config, in one `apply` (the normal case: nothing more).
//! - Refused: the core (interfaces, addresses and whatever no section below
//!   takes), then each section on top of what is applied, in the order the
//!   data plane needs them. A refused section stays out, with its reason, in
//!   the log, the health checks, `state.inspect` and `auth.whoami` (every
//!   client warns). Whole sections only: the rule or route at fault is not
//!   isolated (gap G1.3f).
//! - Retried with backoff (1, 2, 4… 60 s), not every second; the log says it
//!   again every 10 minutes while something is still out.
//! - A commit starts from what the data plane holds. A refused section the
//!   commit does not touch stays out of both sides (as an absent port does,
//!   G1.3b); one it touches goes in, all or nothing like any commit. Safe
//!   Mode and transactions do not change: partial only at boot and on retry.

use corerouter_hal::Hal;
use corerouter_model::config::Config;
use serde::Serialize;

use crate::Session;

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
    pub error: String,
}

/// What [`staged`] left in the data plane.
pub(crate) struct Staged {
    pub applied: Config,
    pub failed: Vec<BootFailure>,
}

/// Apply `target` over `base` (what the data plane holds): whole first; if
/// refused, the core, then section by section. The data plane ends holding
/// `applied` (`base` when even the core is refused).
pub(crate) fn staged(hal: &mut dyn Hal, base: &Config, target: &Config) -> Staged {
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
            failed: vec![BootFailure {
                section: CORE,
                error: if first.is_empty() || e.to_string() == first {
                    e.to_string()
                } else {
                    format!("{e} (whole config: {first})")
                },
            }],
        };
    }
    let mut failed = Vec::new();
    for s in SECTIONS {
        if (s.same)(&applied, target) {
            continue;
        }
        let mut next = applied.clone();
        (s.take)(&mut next, target);
        match hal.apply(&applied, &next) {
            Ok(()) => applied = next,
            Err(e) => failed.push(BootFailure {
                section: s.name,
                error: e.to_string(),
            }),
        }
    }
    Staged { applied, failed }
}

/// Backoff of the retries, seconds.
const RETRY_MAX: u64 = 60;
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
}

/// One line for `storage.boot_apply_error` and the old log lines.
pub(crate) fn summary(failed: &[BootFailure]) -> Option<String> {
    if failed.is_empty() {
        return None;
    }
    Some(
        failed
            .iter()
            .map(|f| format!("{}: {}", f.section, f.error))
            .collect::<Vec<_>>()
            .join("; "),
    )
}

/// The boot's outcome, logged and kept for the retries.
pub(crate) fn at_boot(hal: &mut dyn Hal, target: &Config) -> BootApply {
    let s = staged(hal, &Config::default(), target);
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
        log::error!(
            "{what}: section {} not applied, the rest is (retried with backoff): {}",
            f.section,
            f.error
        );
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

    /// The parts of the config the boot left out, for the health checks
    /// and `auth.whoami`.
    pub fn boot_failures(&self) -> Vec<BootFailure> {
        self.ext::<BootApply>()
            .map(|b| b.failed.clone())
            .unwrap_or_default()
    }

    /// `to` without the refused sections a commit from `running` does not
    /// touch (they stay as the data plane has them). `None`: nothing to
    /// mask (no boot pending, or the core itself is out).
    pub(crate) fn boot_mask(&self, running: &Config, to: &Config) -> Option<Config> {
        let b = self.ext::<BootApply>().filter(|b| b.pending() && !b.nothing())?;
        let mut out: Option<Config> = None;
        for f in &b.failed {
            if let Some(s) = section(f.section)
                && (s.same)(running, to)
            {
                (s.take)(out.get_or_insert_with(|| to.clone()), &b.applied);
            }
        }
        out
    }

    /// The refused sections a commit from `running` to `to` leaves alone.
    pub(crate) fn boot_untouched(&self, running: &Config, to: &Config) -> Vec<&'static str> {
        let Some(b) = self.ext::<BootApply>().filter(|b| b.pending() && !b.nothing()) else {
            return Vec::new();
        };
        b.failed
            .iter()
            .filter(|f| section(f.section).is_some_and(|s| (s.same)(running, to)))
            .map(|f| f.section)
            .collect()
    }

    /// A commit reached the data plane, which holds `applied` now: the
    /// refused sections it included (all but `untouched`) are in.
    pub(crate) fn boot_committed(&mut self, untouched: &[&'static str], applied: Config) {
        let Some(b) = self.ext_mut::<BootApply>() else {
            return;
        };
        if !b.pending() {
            return;
        }
        b.failed.retain(|f| untouched.contains(&f.section));
        b.applied = applied;
        b.next_try = 0;
        b.delay = 1;
        if b.failed.is_empty() {
            log::info!("the whole config reached the data plane with this commit");
            *b = BootApply::default();
        }
        self.publish_boot();
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
        let tried = crate::guard::run("boot apply", || {
            Ok::<_, crate::EngineError>(staged(self.hal_mut(), &base, &target))
        });
        let Some(b) = self.ext_mut::<BootApply>() else {
            return;
        };
        let s = match tried {
            Ok(s) => s,
            Err(e) => Staged {
                applied: base,
                failed: vec![BootFailure {
                    section: CORE,
                    error: e.to_string(),
                }],
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
        b.next_try = now.saturating_add(b.delay);
        b.delay = b.delay.saturating_mul(2).min(RETRY_MAX);
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

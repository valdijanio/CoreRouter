//! G2.3h: does `nf_conntrack_max` hold the CGNAT pools' subscribers?
//!
//! Every translated connection is a conntrack entry. With the table full the
//! kernel drops new connections ("nf_conntrack: table full, dropping
//! packet"), whatever ports the pool still has. The kernel's own limit on a
//! machine with more than 4 GB is 262 144 entries, less than 1280
//! subscribers × 300 connections: the notebook of dev.595 had exactly that.
//!
//! The demand is the subscribers of the enabled pools × the connections a
//! subscriber keeps open at once (`ip.firewall.cgnat.set
//! connections_per_subscriber`, 300 by default: **estimado**, between the
//! 100 and 1500 of the 6WIND CG-NAT dimensioning table). The limit is the
//! one the configuration sets (System › Tuning), else the kernel's.
//!
//! The suggestion: the first Tuning profile (balanced, then throughput)
//! whose `nf_conntrack_max` holds the demand on this machine; else the
//! demand itself as `max_entries`, when the RAM allows it.

use corerouter_model::Config;
use serde_json::{Value, json};

use crate::Session;
use crate::tuning::{CONNTRACK_ENTRY_BYTES, Profile, range, recommend};

/// The Tuning parameter of the limit.
pub const MAX: &str = "net.netfilter.nf_conntrack_max";
/// Chip text of the warning in the pool checks.
pub const LABEL: &str = "conntrack";

/// The demand of `cfg`'s CGNAT: subscribers of the enabled pools, the
/// connections of each and the limit the configuration sets (`None`:
/// the kernel's).
pub fn demand(cfg: &Config) -> (u64, u64, Option<u64>) {
    let c = &cfg.ip.cgnat;
    let subscribers = c.pools.iter().filter(|p| !p.disabled).map(|p| p.subscribers()).sum();
    let set = cfg.system.tuning.sysctl.get(MAX).and_then(|v| u64::try_from(*v).ok());
    (subscribers, u64::from(c.settings.connections_per_subscriber), set)
}

/// What the check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fit {
    pub subscribers: u64,
    pub per_subscriber: u64,
    /// subscribers × per_subscriber.
    pub needed: u64,
    pub max: u64,
    /// Whether `max` is the configured value (else the kernel's).
    pub configured: bool,
    /// The first profile that holds `needed`, and its limit here.
    pub profile: Option<(Profile, u64)>,
    /// The limit to set by hand: `needed`, up to a multiple of 65 536.
    pub max_entries: u64,
    /// Whether the RAM allows `max_entries` (Tuning keeps the table under a
    /// quarter of it).
    pub ram_ok: bool,
}

impl Fit {
    pub fn fits(&self) -> bool {
        self.needed <= self.max
    }

    /// The warning, in English (API), with what to do.
    pub fn warning(&self) -> Option<String> {
        if self.fits() {
            return None;
        }
        let fix = match (self.profile, self.ram_ok) {
            (Some((p, v)), _) => format!(
                "apply the {} profile in System › Tuning (nf_conntrack_max {}) or set ip.firewall.connection.tracking.set max_entries={}",
                p.id(),
                grouped(v),
                self.max_entries
            ),
            (None, true) => format!("set ip.firewall.connection.tracking.set max_entries={}", self.max_entries),
            (None, false) => format!(
                "this machine's RAM does not hold {} entries ({} MiB): fewer subscribers per router or fewer connections each",
                grouped(self.max_entries),
                self.max_entries.saturating_mul(CONNTRACK_ENTRY_BYTES) >> 20
            ),
        };
        Some(format!(
            "conntrack too small: {} subscribers × {} connections = {} entries, above nf_conntrack_max {}: new connections are dropped when the table fills; {fix}",
            grouped(self.subscribers),
            self.per_subscriber,
            grouped(self.needed),
            grouped(self.max)
        ))
    }

    pub fn to_json(&self) -> Value {
        json!({
            "subscribers": self.subscribers,
            "per_subscriber": self.per_subscriber,
            "needed": self.needed,
            "max": self.max,
            "configured": self.configured,
            "fits": self.fits(),
            "profile": self.profile.map(|(p, _)| p.id()),
            "profile_max": self.profile.map(|(_, v)| v),
            "max_entries": self.max_entries,
            "ram_ok": self.ram_ok,
            "warning": self.warning(),
        })
    }
}

/// The check for a demand from [`demand`]; `None` without subscribers or
/// without a limit to compare (no conntrack in this kernel).
pub fn fit(s: &mut Session, (subscribers, per_subscriber, set): (u64, u64, Option<u64>)) -> Option<Fit> {
    if subscribers == 0 {
        return None;
    }
    let (max, configured) = match set {
        Some(v) => (v, true),
        None => {
            let now = s.hal_mut().sysctls(&[MAX]).ok()?;
            (now.get(MAX).copied().flatten().and_then(|v| u64::try_from(v).ok())?, false)
        }
    };
    let needed = subscribers.saturating_mul(per_subscriber);
    let m = crate::cmd::tuning::machine(s);
    let profile = m.as_ref().and_then(|m| {
        [Profile::Balanced, Profile::Throughput].into_iter().find_map(|p| {
            let v = recommend(p, m).get(MAX).and_then(|r| u64::try_from(r.value).ok())?;
            (v >= needed).then_some((p, v))
        })
    });
    let max_entries = needed.div_ceil(65_536).saturating_mul(65_536).max(65_536);
    let cap = corerouter_model::tuning::param(MAX).map(|p| range(p, m.as_ref()).1);
    let ram_ok = cap.is_none_or(|c| i64::try_from(max_entries).is_ok_and(|e| e <= c));
    Some(Fit { subscribers, per_subscriber, needed, max, configured, profile, max_entries, ram_ok })
}

/// `n` with spaces between thousands from five digits on (`384 000`,
/// `1280`), as the GUI writes numbers.
fn grouped(n: u64) -> String {
    let d = n.to_string();
    if d.len() < 5 {
        return d;
    }
    let mut out = String::new();
    for (i, c) in d.chars().enumerate() {
        if i > 0 && (d.len() - i).is_multiple_of(3) {
            out.push(' ');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_read_well() {
        assert_eq!(grouped(384_000), "384 000");
        assert_eq!(grouped(262_144), "262 144");
        assert_eq!(grouped(999), "999");
        assert_eq!(grouped(1_280), "1280");
        assert_eq!(grouped(10_000), "10 000");
    }
}

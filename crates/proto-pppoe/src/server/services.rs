//! The Service-Name table of one server (G4.3k): several services on one
//! port, in one SESSION_ID space, the way Junos `service-name-tables` do.
//!
//! Every name a subscriber asks for lands on exactly one row: a named row
//! whose name matches byte for byte, else the `empty` row (zero-length
//! Service-Name, RFC 2516 Appendix A: "any service is acceptable"), else
//! the `any` row (every other name). Each row says what happens:
//!
//! - **terminate**: PADO at once (plus the server's load delay);
//! - **delay**: PADO after `delay_ms` more, so another BNG that terminates
//!   the name answers first (a backup);
//! - **drop**: no PADO (RFC 2516 §5.2: "MUST NOT respond with a PADO" if
//!   it cannot serve the PADI) and, at the PADR, a PADS with
//!   Service-Name-Error and SESSION_ID 0 (§5.4).
//!
//! RFC 2516 §9 RECOMMENDS never refusing by Service-Name (a refusal tells a
//! scanner which names exist): the defaults (`ServiceTable::default`)
//! terminate everything; refusing is the operator's choice.

use std::collections::HashMap;

use crate::guard::PadiLimiter;
use crate::timer::Millis;
use crate::wire::Mac;

/// What a row does with a PADI (Junos `terminate`, `delay`, `drop`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ServiceAction {
    #[default]
    Terminate,
    Delay,
    Drop,
}

/// One row's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ServiceRule {
    pub action: ServiceAction,
    /// With [`ServiceAction::Delay`]: ms before the PADO, on top of the
    /// server's load delay.
    pub delay_ms: u32,
    /// Sessions this row may hold (Junos `max-sessions`); 0 = no limit.
    pub max_sessions: u32,
    /// PADIs answered per second for this row; 0 = no limit.
    pub padi_limit: u32,
}

/// Which row a name landed on: [`EMPTY`], [`ANY`] or `NAMED + i`.
pub type ServiceSlot = u16;
pub const EMPTY: ServiceSlot = 0;
pub const ANY: ServiceSlot = 1;
pub const NAMED: ServiceSlot = 2;

/// Rows a table may hold (Junos: 512 named services on the whole router).
pub const MAX_NAMED: usize = 512;

/// The table. Named rows are matched in order; names are unique (the
/// engine refuses duplicates, `ServiceTable::new` keeps the first).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceTable {
    named: Vec<(Box<[u8]>, ServiceRule)>,
    /// Name → index in `named` (a linear walk of 512 names cost 0.84 µs
    /// per PADI, **medido**; the hash keeps it flat).
    index: HashMap<Box<[u8]>, u16>,
    pub empty: ServiceRule,
    pub any: ServiceRule,
}

impl Default for ServiceTable {
    /// RouterOS `service-name=""`: every name, and the empty one, served.
    fn default() -> Self {
        ServiceTable {
            named: Vec::new(),
            index: HashMap::new(),
            empty: ServiceRule::default(),
            any: ServiceRule::default(),
        }
    }
}

impl ServiceTable {
    /// `named` rows (duplicates after the first and rows past
    /// [`MAX_NAMED`] are left out), then the empty and any rows.
    pub fn new(
        named: impl IntoIterator<Item = (Vec<u8>, ServiceRule)>,
        empty: ServiceRule,
        any: ServiceRule,
    ) -> ServiceTable {
        let mut rows: Vec<(Box<[u8]>, ServiceRule)> = Vec::new();
        for (n, r) in named {
            if rows.len() >= MAX_NAMED {
                break;
            }
            if !n.is_empty() && !rows.iter().any(|(m, _)| **m == *n) {
                rows.push((n.into(), r));
            }
        }
        let index = rows
            .iter()
            .enumerate()
            .filter_map(|(i, (n, _))| Some((n.clone(), u16::try_from(i).ok()?)))
            .collect();
        ServiceTable {
            named: rows,
            index,
            empty,
            any,
        }
    }

    /// RouterOS `service-name=<names>`: those names and the empty one are
    /// served, any other name is not.
    pub fn only<N: AsRef<[u8]>>(names: &[N]) -> ServiceTable {
        ServiceTable::new(
            names
                .iter()
                .map(|n| (n.as_ref().to_vec(), ServiceRule::default())),
            ServiceRule::default(),
            ServiceRule {
                action: ServiceAction::Drop,
                ..ServiceRule::default()
            },
        )
    }

    /// The row of `name` (once per PADI/PADR, never per data packet).
    pub fn lookup(&self, name: &[u8]) -> (ServiceSlot, &ServiceRule) {
        if name.is_empty() {
            return (EMPTY, &self.empty);
        }
        match self.index.get(name) {
            Some(&i) => {
                let slot = NAMED.saturating_add(i);
                (slot, self.rule(slot))
            }
            None => (ANY, &self.any),
        }
    }

    /// The rule of a slot (a slot past the table, after a reconfigure,
    /// reads as the any row).
    pub fn rule(&self, slot: ServiceSlot) -> &ServiceRule {
        match slot {
            EMPTY => &self.empty,
            ANY => &self.any,
            s => self
                .named
                .get(usize::from(s - NAMED))
                .map_or(&self.any, |(_, r)| r),
        }
    }

    /// Slots in use: empty, any and one per named row.
    pub fn slots(&self) -> usize {
        usize::from(NAMED) + self.named.len()
    }

    pub fn named(&self) -> impl Iterator<Item = (&[u8], &ServiceRule)> {
        self.named.iter().map(|(n, r)| (&**n, r))
    }
}

/// Per-row state a server keeps next to its table: sessions held and the
/// PADI limiter.
pub(crate) struct ServiceState {
    pub active: Vec<u32>,
    limiters: Vec<Option<PadiLimiter>>,
}

impl ServiceState {
    pub fn new(t: &ServiceTable) -> ServiceState {
        let n = t.slots();
        let limiter =
            |r: &ServiceRule| (r.padi_limit > 0).then(|| PadiLimiter::new(r.padi_limit, 0, 0));
        let mut limiters = Vec::with_capacity(n);
        limiters.push(limiter(&t.empty));
        limiters.push(limiter(&t.any));
        limiters.extend(t.named.iter().map(|(_, r)| limiter(r)));
        ServiceState {
            active: vec![0; n],
            limiters,
        }
    }

    pub fn full(&self, t: &ServiceTable, slot: ServiceSlot) -> bool {
        let max = t.rule(slot).max_sessions;
        max > 0
            && self
                .active
                .get(usize::from(slot))
                .is_some_and(|n| *n >= max)
    }

    pub fn allow(&mut self, now: Millis, slot: ServiceSlot, mac: Mac) -> bool {
        match self.limiters.get_mut(usize::from(slot)) {
            Some(Some(l)) => l.allow(now, mac),
            _ => true,
        }
    }

    pub fn add(&mut self, slot: ServiceSlot) {
        if let Some(n) = self.active.get_mut(usize::from(slot)) {
            *n = n.saturating_add(1);
        }
    }

    pub fn remove(&mut self, slot: ServiceSlot) {
        if let Some(n) = self.active.get_mut(usize::from(slot)) {
            *n = n.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drop_rule() -> ServiceRule {
        ServiceRule {
            action: ServiceAction::Drop,
            ..ServiceRule::default()
        }
    }

    #[test]
    fn every_name_lands_on_exactly_one_row() {
        let t = ServiceTable::new(
            [
                (b"internet".to_vec(), ServiceRule::default()),
                (b"iptv".to_vec(), drop_rule()),
                (b"internet".to_vec(), drop_rule()),
                (Vec::new(), drop_rule()),
            ],
            ServiceRule::default(),
            drop_rule(),
        );
        assert_eq!(
            t.named().count(),
            2,
            "duplicates and the empty name left out"
        );
        assert_eq!(t.lookup(b"internet"), (NAMED, &ServiceRule::default()));
        assert_eq!(t.lookup(b"iptv").0, NAMED + 1);
        assert_eq!(t.lookup(b"").0, EMPTY);
        assert_eq!(t.lookup(b"voip").0, ANY);
        assert_eq!(
            t.lookup(b"INTERNET").0,
            ANY,
            "byte for byte, no case folding"
        );
        assert_eq!(t.rule(NAMED + 9), &t.any);
    }

    #[test]
    fn routeros_shorthands() {
        let all = ServiceTable::default();
        assert_eq!(all.lookup(b"x").1.action, ServiceAction::Terminate);
        let only = ServiceTable::only(&["isp"]);
        assert_eq!(only.lookup(b"isp").1.action, ServiceAction::Terminate);
        assert_eq!(only.lookup(b"").1.action, ServiceAction::Terminate);
        assert_eq!(only.lookup(b"x").1.action, ServiceAction::Drop);
    }

    #[test]
    fn per_row_limits() {
        let t = ServiceTable::new(
            [(
                b"a".to_vec(),
                ServiceRule {
                    max_sessions: 2,
                    padi_limit: 1,
                    ..ServiceRule::default()
                },
            )],
            ServiceRule::default(),
            ServiceRule::default(),
        );
        let mut s = ServiceState::new(&t);
        s.add(NAMED);
        assert!(!s.full(&t, NAMED));
        s.add(NAMED);
        assert!(s.full(&t, NAMED) && !s.full(&t, ANY));
        s.remove(NAMED);
        assert!(!s.full(&t, NAMED));
        assert!(s.allow(0, NAMED, Mac::ZERO));
        assert!(!s.allow(1, NAMED, Mac::ZERO), "1 PADI/s for this row");
        assert!(s.allow(1, ANY, Mac::ZERO));
    }
}

//! Counters of the engine itself since the process started (G4.4): what
//! `system.metrics` reports and the daemon's `/metrics` exposes. Operational
//! state, never saved; a restart starts them at zero, which Prometheus
//! counters allow (`rate()` treats a drop as a reset).

use serde::Serialize;

/// How many commands ran and how many commits were tried, by outcome.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct EngineCounters {
    /// Commands that change the config (journaled), ok / failed.
    pub changes_ok: u64,
    pub changes_failed: u64,
    /// Read-only commands (queries), ok / failed.
    pub queries_ok: u64,
    pub queries_failed: u64,
    /// Ids that are not commands at all.
    pub unknown: u64,
    /// Commits applied to the data plane / refused (validation, lockout,
    /// the platform rejecting the change).
    pub commits_ok: u64,
    pub commits_failed: u64,
}

impl EngineCounters {
    /// One command finished; `journal` is `None` for an unknown id.
    pub fn note_command(&mut self, journal: Option<bool>, ok: bool) {
        let n = match (journal, ok) {
            (None, _) => &mut self.unknown,
            (Some(true), true) => &mut self.changes_ok,
            (Some(true), false) => &mut self.changes_failed,
            (Some(false), true) => &mut self.queries_ok,
            (Some(false), false) => &mut self.queries_failed,
        };
        *n = n.saturating_add(1);
    }

    pub fn note_commit(&mut self, ok: bool) {
        let n = if ok {
            &mut self.commits_ok
        } else {
            &mut self.commits_failed
        };
        *n = n.saturating_add(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_by_kind_and_outcome() {
        let mut c = EngineCounters::default();
        c.note_command(Some(true), true);
        c.note_command(Some(true), false);
        c.note_command(Some(false), true);
        c.note_command(None, false);
        c.note_commit(true);
        c.note_commit(false);
        c.note_commit(false);
        assert_eq!(
            c,
            EngineCounters {
                changes_ok: 1,
                changes_failed: 1,
                queries_ok: 1,
                queries_failed: 0,
                unknown: 1,
                commits_ok: 1,
                commits_failed: 2,
            }
        );
    }

    #[test]
    fn counters_saturate_instead_of_wrapping() {
        let mut c = EngineCounters {
            commits_ok: u64::MAX,
            ..Default::default()
        };
        c.note_commit(true);
        assert_eq!(c.commits_ok, u64::MAX);
    }
}

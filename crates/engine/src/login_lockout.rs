//! Account lockouts of the control channel (G0.12) as the engine sees them.
//!
//! The control channel (`corerouter-control`, `auth::Gate`) counts failed
//! logins and holds out a user name attacked from several sources; it
//! registers itself here so `user.lockout.list` and `user.lockout.clear`
//! are commands like any other (Junos `show system login lockout` and
//! `clear system login lockout user`). The engine keeps no counter of its
//! own: the gate owns them, on its monotonic clock.

use std::sync::Arc;

use serde::Serialize;

use crate::Session;

/// One user name with failed logins counted now.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UserLockout {
    pub user: String,
    /// Failed logins in the current window (while locked: the ones that
    /// started the lock).
    pub failures: u32,
    /// Distinct sources (an IPv4 address or an IPv6 /64) they came from.
    pub sources: u32,
    /// Attempts refused during the current lock (any source but loopback
    /// and the known ones).
    pub refused: u32,
    /// Seconds the name stays locked for network logins; 0 = not locked.
    pub locked_secs: u64,
    /// Locks in a row (each one twice as long as the one before).
    pub blocks: u32,
    /// Sources this user logged in from before: never locked out.
    pub known_sources: u32,
}

/// What a login gate offers.
pub trait LoginLockouts: Send + Sync {
    /// The names with failures or a lock, locked ones first.
    fn lockouts(&self) -> Vec<UserLockout>;
    /// Lift the lock and forget the failures of `user` (all without it);
    /// how many names were cleared.
    fn lockout_clear(&self, user: Option<&str>) -> usize;
}

#[derive(Default)]
struct Gates(Vec<Arc<dyn LoginLockouts>>);

/// Most gates registered (a daemon has two: local and remote).
const MAX_GATES: usize = 8;

impl Session {
    /// A control-channel gate whose lockouts the commands show.
    pub fn add_login_lockouts(&mut self, gate: Arc<dyn LoginLockouts>) {
        if let Some(g) = self.ext_mut::<Gates>()
            && g.0.len() < MAX_GATES
        {
            g.0.push(gate);
        }
    }

    /// Every registered gate's lockouts (empty without a control channel).
    pub fn login_lockouts(&self) -> Vec<UserLockout> {
        let Some(g) = self.ext::<Gates>() else {
            return Vec::new();
        };
        let mut rows: Vec<UserLockout> = g.0.iter().flat_map(|g| g.lockouts()).collect();
        rows.sort_by(|a, b| {
            b.locked_secs
                .cmp(&a.locked_secs)
                .then(b.failures.cmp(&a.failures))
                .then(a.user.cmp(&b.user))
        });
        rows
    }

    /// `true` when some control channel registered its gate.
    pub fn has_login_lockouts(&self) -> bool {
        self.ext::<Gates>().is_some_and(|g| !g.0.is_empty())
    }

    pub fn login_lockout_clear(&self, user: Option<&str>) -> usize {
        let Some(g) = self.ext::<Gates>() else {
            return 0;
        };
        g.0.iter().map(|g| g.lockout_clear(user)).sum()
    }
}

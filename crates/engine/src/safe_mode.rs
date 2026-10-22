//! Safe Mode, as in RouterOS: a dead-man switch for remote changes.
//!
//! `config.safe-mode.enter` remembers the running config. Every change made
//! afterwards — by any client, as in RouterOS — stays pending: it runs on the
//! data plane but is not saved as the boot config. Then:
//!
//! - `config.safe-mode.exit` confirms: the changes are saved and kept;
//! - `config.safe-mode.cancel`, the owner's connection closing
//!   ([`Session::hang_up`]) or the optional timeout expiring undo them: the
//!   config from the entry is committed again as a new revision;
//! - a restart in the middle boots the entry config, because nothing was
//!   saved since the entry (G0.6 storage still holds it).
//!
//! The engine has no clock of its own (it compiles for wasm32): time comes
//! from [`Hal::now_unix`](corerouter_hal::Hal::now_unix) or from
//! [`Session::tick`], which the daemon calls every second. Expiry is checked
//! on every tick and before every command.

use corerouter_model::Config;
use serde::Serialize;
use serde_json::{Value, json};

use crate::auth::Principal;
use crate::lockout::Link;
use crate::{EngineError, Result, Session};

/// Who sent a command. The control channel gives each connection its own
/// id; commands from inside the process (the GUI lab, tests) are [`Caller::local`].
///
/// A new connection starts [`Principal::Anonymous`] (no rights); the
/// control channel sets the principal of each request after checking its
/// token (G0.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Caller {
    pub id: u64,
    /// Shown to other operators: "tcp 127.0.0.1:50412".
    pub name: String,
    #[serde(skip)]
    pub principal: Principal,
    /// Its TCP connection, for the lockout check (`None`: inside the
    /// process, nothing to lose).
    #[serde(skip)]
    pub link: Option<Link>,
}

impl Caller {
    pub const LOCAL_ID: u64 = 0;

    /// A connection that has not logged in yet.
    pub fn new(id: u64, name: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            principal: Principal::Anonymous,
            link: None,
        }
    }

    pub fn local() -> Self {
        Self::new(Self::LOCAL_ID, "local").with_principal(Principal::Local)
    }

    #[must_use]
    pub fn with_link(mut self, link: Link) -> Self {
        self.link = Some(link);
        self
    }

    #[must_use]
    pub fn with_principal(mut self, principal: Principal) -> Self {
        self.principal = principal;
        self
    }
}

impl Default for Caller {
    fn default() -> Self {
        Self::local()
    }
}

/// Bounds of `timeout_secs`: long enough to read the screen and confirm,
/// short enough that a lost router comes back the same day.
pub const MIN_TIMEOUT_SECS: u32 = 10;
pub const MAX_TIMEOUT_SECS: u32 = 86_400;

#[derive(Debug, Clone)]
pub(crate) struct Active {
    owner: Caller,
    /// The running config at the entry: what an undo restores. Kept here,
    /// not looked up in the (bounded) history.
    entry: Config,
    entry_revision: u32,
    since: Option<u64>,
    timeout_secs: Option<u32>,
    deadline: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SafeMode {
    active: Option<Active>,
    /// How the last Safe Mode ended, for `state.inspect` (the owner may be
    /// a client that reconnects after its connection dropped).
    last: Option<String>,
    /// Latest time given to [`Session::tick`].
    clock: Option<u64>,
}

impl SafeMode {
    pub(crate) fn is_active(&self) -> bool {
        self.active.is_some()
    }
}

impl Session {
    /// Advance the clock (seconds since the Unix epoch) and undo an expired
    /// Safe Mode. The daemon calls this every second.
    pub fn tick(&mut self, now_unix: u64) {
        self.safe_mode_mut().clock = Some(now_unix);
        self.expire_safe_mode();
        self.expire_dynamic_addresses();
        self.expire_tasks();
    }

    /// The connection `caller_id` closed. If it owned Safe Mode, its changes
    /// are undone (that is the whole point: the operator lost the router).
    pub fn hang_up(&mut self, caller_id: u64) {
        let owned = self
            .safe_mode()
            .active
            .as_ref()
            .is_some_and(|a| a.owner.id == caller_id);
        if owned {
            let reason = "the owner's connection closed";
            let result = self.undo_safe_mode(reason);
            self.record_automatic("config.safe-mode.cancel", reason, &result);
        }
    }

    pub(crate) fn now(&self) -> Option<u64> {
        self.hal_now().or(self.safe_mode().clock)
    }

    /// Undo if the deadline passed. Called before every command.
    pub(crate) fn expire_safe_mode(&mut self) {
        let now = self.now();
        let expired = self
            .safe_mode()
            .active
            .as_ref()
            .and_then(|a| a.deadline)
            .zip(now)
            .is_some_and(|(deadline, now)| now >= deadline);
        if expired {
            let reason = "the timeout expired without confirmation";
            let result = self.undo_safe_mode(reason);
            self.record_automatic("config.safe-mode.cancel", reason, &result);
        }
    }

    pub(crate) fn safe_mode_enter(&mut self, timeout_secs: Option<u32>) -> Result<Value> {
        if let Some(t) = timeout_secs
            && !(MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&t)
        {
            return Err(EngineError::bad(
                "timeout_secs",
                format!("must be {MIN_TIMEOUT_SECS}..={MAX_TIMEOUT_SECS} seconds"),
            ));
        }
        let now = self.now();
        let deadline = match (timeout_secs, now) {
            (None, _) => None,
            (Some(t), Some(now)) => Some(now.saturating_add(u64::from(t))),
            (Some(_), None) => {
                return Err(EngineError::bad(
                    "timeout_secs",
                    "this router has no clock yet (the daemon ticks it every second); \
                     enter without a timeout",
                ));
            }
        };
        let caller = self.caller().clone();
        if let Some(a) = self.safe_mode().active.as_ref() {
            if a.owner.id != caller.id {
                return Err(disabled("config.safe-mode.enter", held_by(a, now)));
            }
        } else if self.store().is_dirty() {
            return Err(disabled(
                "config.safe-mode.enter",
                format!(
                    "commit or discard the {} pending change(s) first (config.diff)",
                    self.store().diff().len()
                ),
            ));
        }
        let entry_revision = self.store().current_revision();
        let entry = self.store().running().clone();
        let state = self.safe_mode_mut();
        match state.active.as_mut() {
            // The owner again: re-arm the timeout, keep the entry point.
            Some(a) => {
                a.timeout_secs = timeout_secs;
                a.deadline = deadline;
            }
            None => {
                state.active = Some(Active {
                    owner: caller,
                    entry,
                    entry_revision,
                    since: now,
                    timeout_secs,
                    deadline,
                });
                log::info!("safe mode entered at revision {entry_revision}");
            }
        }
        Ok(self.safe_mode_summary())
    }

    /// Confirm: keep and save everything done since the entry.
    pub(crate) fn safe_mode_exit(&mut self, force: bool) -> Result<Value> {
        let active = self.take_owned("config.safe-mode.exit", force)?;
        let from = active.entry_revision;
        let to = self.store().current_revision();
        let msg = if to == from {
            format!("left with no changes (revision {to})")
        } else {
            format!("confirmed revisions {}..={to}", from.saturating_add(1))
        };
        log::info!("safe mode: {msg}");
        self.safe_mode_mut().last = Some(msg);
        self.save();
        Ok(self.safe_mode_summary())
    }

    /// Undo now: back to the config of the entry.
    pub(crate) fn safe_mode_cancel(&mut self, force: bool) -> Result<Value> {
        let active = self.take_owned("config.safe-mode.cancel", force)?;
        // Put it back so the undo below finds it (and reports the same way
        // as a timeout or a dropped connection).
        self.safe_mode_mut().active = Some(active);
        let reason = if force {
            format!("cancelled by {}", self.caller().name)
        } else {
            "cancelled".to_owned()
        };
        self.undo_safe_mode(&reason)
            .map(|_| self.safe_mode_summary())
    }

    /// `state.inspect` → `safe_mode`.
    pub(crate) fn safe_mode_summary(&self) -> Value {
        let state = self.safe_mode();
        let Some(a) = state.active.as_ref() else {
            return json!({ "active": false, "last": state.last });
        };
        let now = self.now();
        json!({
            "active": true,
            "owner": a.owner.name,
            "yours": a.owner.id == self.caller().id,
            "since": a.since,
            "entry_revision": a.entry_revision,
            "pending_revisions": self.store().current_revision().saturating_sub(a.entry_revision),
            "timeout_secs": a.timeout_secs,
            "expires_in": a.deadline.zip(now).map(|(d, n)| d.saturating_sub(n)),
            "last": state.last,
        })
    }

    fn take_owned(&mut self, id: &str, force: bool) -> Result<Active> {
        let caller_id = self.caller().id;
        let now = self.now();
        let state = self.safe_mode_mut();
        let Some(a) = state.active.as_ref() else {
            return Err(disabled(id, "not in Safe Mode".into()));
        };
        if a.owner.id != caller_id && !force {
            return Err(disabled(
                id,
                format!("{}; pass force: true to end it from here", held_by(a, now)),
            ));
        }
        state
            .active
            .take()
            .ok_or_else(|| EngineError::Internal(id.to_owned()))
    }

    /// Restore the entry config as a new revision and leave Safe Mode. On
    /// failure Safe Mode is left anyway (its owner may be gone) and the
    /// error is kept in `last`; the boot config is still the entry one.
    fn undo_safe_mode(&mut self, reason: &str) -> Result<Option<u32>> {
        let Some(active) = self.safe_mode_mut().active.take() else {
            return Ok(None);
        };
        let from = active.entry_revision;
        let candidate = self.store().candidate().clone();
        self.store_mut().set_candidate(active.entry);
        let result = if self.store().is_dirty() {
            self.commit_restoring(&format!("safe mode undo: {reason}"))
                .map(Some)
        } else {
            Ok(None)
        };
        let msg = match &result {
            Ok(Some(rev)) => {
                format!("undone ({reason}): config of revision {from} restored as revision {rev}")
            }
            Ok(None) => format!("ended ({reason}); nothing to undo since revision {from}"),
            Err(e) => {
                self.store_mut().set_candidate(candidate);
                format!(
                    "UNDO FAILED ({reason}): {e}; the router still runs revision {}, \
                     config.rollback {{revision: {from}}} restores the entry",
                    self.store().current_revision()
                )
            }
        };
        if result.is_err() {
            log::error!("safe mode: {msg}");
        } else {
            log::warn!("safe mode: {msg}");
        }
        self.safe_mode_mut().last = Some(msg);
        result
    }
}

fn disabled(id: &str, reason: String) -> EngineError {
    EngineError::Disabled {
        id: id.to_owned(),
        reason,
    }
}

/// "Safe Mode is held by tcp 127.0.0.1:50412 since 2026-10-21 14:03:09 UTC
/// (40 s ago), entered at revision 3".
fn held_by(a: &Active, now: Option<u64>) -> String {
    let since = match (a.since, now) {
        (Some(s), Some(n)) => format!(" since {} ({} s ago)", utc(s), n.saturating_sub(s)),
        (Some(s), None) => format!(" since {}", utc(s)),
        _ => String::new(),
    };
    format!(
        "Safe Mode is held by {}{since}, entered at revision {}",
        a.owner.name, a.entry_revision
    )
}

/// `YYYY-MM-DD HH:MM:SS UTC` (proleptic Gregorian, days-from-civil inverse).
pub(crate) fn utc(secs: u64) -> String {
    let days = i64::try_from(secs / 86_400).unwrap_or(i64::MAX / 2);
    let rem = secs % 86_400;
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe
        .saturating_add(era.saturating_mul(400))
        .saturating_add(i64::from(month <= 2));
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rem / 3_600,
        rem % 3_600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_utc() {
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(utc(1_792_591_389), "2026-10-21 14:03:09 UTC");
        // Never panics, even far out.
        assert!(!utc(u64::MAX).is_empty());
    }
}

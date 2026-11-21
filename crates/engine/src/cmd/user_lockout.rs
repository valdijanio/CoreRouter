//! `user.lockout.*` (G0.12): the user names the control channel holds out
//! after failed logins from several sources, and the way to let them back
//! in. Junos `show system login lockout` / `clear system login lockout`,
//! Cisco `clear aaa local user lockout`; RouterOS has neither (it only
//! delays each failed login). Group `full`, as every `user.*` command.

use serde_json::{Value, json};

use super::CommandSpec;
use super::args::{opt_str, opt_u32};
use crate::{EngineError, Result, Session};

/// Rows a list gives by default, and at most.
const LIST_DEFAULT: u32 = 100;
const LIST_MAX: u32 = 10_000;
/// Longest name the gate keeps (longer ones are cut there).
const MAX_USER: usize = 64;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "user.lockout.list", "Login Lockouts", ["System", "Users"], None,
        "{limit?: int 1..10000 (default 100)} → {total, locked (names locked now), running (a control channel counts), rows: [{user, failures (in the window; locked: the ones that started it), sources (distinct addresses or IPv6 /64s), refused (attempts refused while locked), locked_secs (0 = not locked), blocks (locks in a row), known_sources (never locked out)}]}",
        super::always, list),
    cmd!("user.lockout.clear", "Clear Login Lockouts", ["System", "Users"], None,
        "{user?: string (this name; without it: all)} → {cleared}",
        super::always, clear),
];

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let limit = opt_u32(p, "limit")?.unwrap_or(LIST_DEFAULT);
    if !(1..=LIST_MAX).contains(&limit) {
        return Err(EngineError::bad("limit", format!("1..={LIST_MAX}")));
    }
    let rows = s.login_lockouts();
    let locked = rows.iter().filter(|r| r.locked_secs > 0).count();
    let total = rows.len();
    let rows: Vec<_> = rows.into_iter().take(limit as usize).collect();
    Ok(json!({
        "total": total,
        "locked": locked,
        "running": s.has_login_lockouts(),
        "rows": serde_json::to_value(rows).map_err(|e| EngineError::Internal(e.to_string()))?,
    }))
}

fn clear(s: &mut Session, p: &Value) -> Result<Value> {
    let user = opt_str(p, "user")?;
    if let Some(u) = user
        && (u.is_empty() || u.len() > MAX_USER)
    {
        return Err(EngineError::bad("user", format!("1..={MAX_USER} bytes")));
    }
    Ok(json!({"cleared": s.login_lockout_clear(user)}))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::login_lockout::{LoginLockouts, UserLockout};

    #[derive(Default)]
    struct Fake(Mutex<Vec<UserLockout>>);

    impl LoginLockouts for Fake {
        fn lockouts(&self) -> Vec<UserLockout> {
            self.0.lock().unwrap().clone()
        }
        fn lockout_clear(&self, user: Option<&str>) -> usize {
            let mut r = self.0.lock().unwrap();
            let before = r.len();
            r.retain(|x| user.is_some_and(|u| x.user != u));
            before - r.len()
        }
    }

    fn row(user: &str, locked_secs: u64) -> UserLockout {
        UserLockout {
            user: user.into(),
            failures: 12,
            sources: 4,
            refused: 0,
            locked_secs,
            blocks: u32::from(locked_secs > 0),
            known_sources: 0,
        }
    }

    #[test]
    fn list_and_clear() {
        let mut s = Session::virtual_lab();
        // Without a control channel: empty, and says so.
        let r = s.execute("user.lockout.list", &json!({})).unwrap();
        assert_eq!(r["running"], false);
        assert_eq!(r["total"], 0);
        assert_eq!(s.execute("user.lockout.clear", &json!({})).unwrap()["cleared"], 0);

        let fake = Arc::new(Fake(Mutex::new(vec![row("root", 0), row("admin", 60)])));
        s.add_login_lockouts(fake.clone());
        let r = s.execute("user.lockout.list", &json!({"limit": 1})).unwrap();
        assert_eq!(r["running"], true);
        assert_eq!(r["total"], 2);
        assert_eq!(r["locked"], 1);
        // Locked first.
        assert_eq!(r["rows"][0]["user"], "admin");
        assert_eq!(r["rows"].as_array().unwrap().len(), 1);
        let r = s.execute("user.lockout.clear", &json!({"user": "admin"})).unwrap();
        assert_eq!(r["cleared"], 1);
        let r = s.execute("user.lockout.list", &json!({})).unwrap();
        assert_eq!(r["total"], 1);
        assert_eq!(r["locked"], 0);
        assert_eq!(s.execute("user.lockout.clear", &json!({})).unwrap()["cleared"], 1);
    }

    #[test]
    fn bad_params_are_refused() {
        let mut s = Session::virtual_lab();
        for p in [
            json!({"limit": 0}),
            json!({"limit": 10_001}),
            json!({"limit": "x"}),
            json!({"other": 1}),
        ] {
            assert!(s.execute("user.lockout.list", &p).is_err(), "{p}");
        }
        for p in [json!({"user": ""}), json!({"user": "x".repeat(65)}), json!({"user": 3})] {
            assert!(s.execute("user.lockout.clear", &p).is_err(), "{p}");
        }
    }

    #[test]
    fn needs_group_full() {
        let spec = crate::cmd::find("user.lockout.list").unwrap();
        assert_eq!(crate::auth::required_group(spec), corerouter_model::Group::Full);
    }
}

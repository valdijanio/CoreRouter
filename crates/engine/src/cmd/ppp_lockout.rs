//! `ppp.lockout.*` (G4.3m): who short-cycle protection holds out now and
//! why, and the way to let them back in. Junos `show pppoe lockout` and
//! `clear pppoe lockout`; RouterOS has neither.

use corerouter_model::MacAddr;
use serde_json::{Value, json};

use super::args::{opt_parse, opt_u32};
use super::{CommandSpec, always};
use crate::{EngineError, Result, Session};

/// Rows a list gives by default, and at most.
const LIST_DEFAULT: u32 = 1000;
const LIST_MAX: u32 = 100_000;

pub(super) const COMMANDS: &[CommandSpec] = &[
    cmd!(query "ppp.lockout.list", "PPP Lockouts", [], None,
        "{limit?: int 1..100000 (default 1000)} → {total (hosts locked out now), running, rows: [{caller_id, server, vlan?, inner_vlan?, strikes (short cycles in a row), left_secs, reason (how its last session ended)}]} (refreshed once a second)",
        always, list),
    cmd!("ppp.lockout.clear", "Clear PPP Lockouts", [], None,
        "{mac?: mac (this host; without it: all)} → {cleared}",
        has_service, clear),
];

fn has_service(s: &Session) -> std::result::Result<(), String> {
    if s.ppp_backend().is_none() {
        Err("the pppoe service is not running (daemon only)".into())
    } else {
        Ok(())
    }
}

fn list(s: &mut Session, p: &Value) -> Result<Value> {
    let limit = opt_u32(p, "limit")?.unwrap_or(LIST_DEFAULT);
    if !(1..=LIST_MAX).contains(&limit) {
        return Err(EngineError::bad("limit", format!("1..={LIST_MAX}")));
    }
    let Some(b) = s.ppp_backend() else {
        return Ok(json!({"total": 0, "running": false, "rows": []}));
    };
    let (total, rows) = b.lockouts(limit as usize);
    Ok(json!({"total": total, "running": true, "rows": rows}))
}

fn clear(s: &mut Session, p: &Value) -> Result<Value> {
    let mac = opt_parse::<MacAddr>(p, "mac")?;
    let Some(b) = s.ppp_backend() else {
        return Err(EngineError::bad("service", "the pppoe service is not running (daemon only)"));
    };
    Ok(json!({"cleared": b.lockout_clear(mac)}))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use std::sync::{Arc, Mutex};

    use corerouter_model::ppp::{ActiveSession, HistoryEntry, LockedOut, ServiceStats, Why};

    use super::*;
    use crate::ppp::PppBackend;

    #[derive(Default)]
    struct Fake {
        rows: Mutex<Vec<LockedOut>>,
    }

    impl PppBackend for Fake {
        fn active(&self) -> Vec<ActiveSession> {
            Vec::new()
        }
        fn terminate(&self, _: &[String]) -> usize {
            0
        }
        fn history(&self) -> Vec<HistoryEntry> {
            Vec::new()
        }
        fn why(&self, _: Option<&str>, _: Option<MacAddr>) -> Why {
            Why::default()
        }
        fn stats(&self) -> ServiceStats {
            ServiceStats::default()
        }
        fn lockouts(&self, limit: usize) -> (usize, Vec<LockedOut>) {
            let r = self.rows.lock().unwrap();
            (r.len(), r.iter().take(limit).cloned().collect())
        }
        fn lockout_clear(&self, mac: Option<MacAddr>) -> usize {
            let mut r = self.rows.lock().unwrap();
            let before = r.len();
            r.retain(|x| mac.is_some_and(|m| x.caller_id != m.to_string()));
            before - r.len()
        }
    }

    fn row(mac: &str) -> LockedOut {
        LockedOut {
            caller_id: mac.into(),
            server: "pppoe-ether2".into(),
            strikes: 3,
            left_secs: 4,
            reason: "auth-failed".into(),
            ..LockedOut::default()
        }
    }

    #[test]
    fn list_and_clear() {
        let mut s = Session::virtual_lab();
        // Without the service: an empty list that says so, and no clear.
        let r = s.execute("ppp.lockout.list", &json!({})).unwrap();
        assert_eq!(r["running"], false);
        assert!(s.execute("ppp.lockout.clear", &json!({})).is_err());

        let m1 = "02:00:00:00:00:01";
        let m2 = "02:00:00:00:00:02";
        let fake = Fake { rows: Mutex::new(vec![row(m1), row(m2)]) };
        s.set_ppp_backend(Arc::new(fake));
        let r = s.execute("ppp.lockout.list", &json!({"limit": 1})).unwrap();
        assert_eq!(r["total"], 2);
        assert_eq!(r["rows"].as_array().unwrap().len(), 1);
        assert_eq!(r["rows"][0]["reason"], "auth-failed");
        let r = s.execute("ppp.lockout.clear", &json!({"mac": m1})).unwrap();
        assert_eq!(r["cleared"], 1);
        let r = s.execute("ppp.lockout.clear", &json!({})).unwrap();
        assert_eq!(r["cleared"], 1);
        assert_eq!(s.execute("ppp.lockout.list", &json!({})).unwrap()["total"], 0);
    }

    #[test]
    fn bad_params_are_refused() {
        let mut s = Session::virtual_lab();
        assert!(s.execute("ppp.lockout.list", &json!({"limit": 0})).is_err());
        assert!(s.execute("ppp.lockout.list", &json!({"limit": 100_001})).is_err());
        let fake = Fake::default();
        s.set_ppp_backend(Arc::new(fake));
        assert!(s.execute("ppp.lockout.clear", &json!({"mac": "zz"})).is_err());
    }
}

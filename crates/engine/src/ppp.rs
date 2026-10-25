//! The PPP service (G4.3d) as the engine sees it. The daemon's `pppoe`
//! service owns the AF_PACKET sockets, the `proto-pppoe` servers and the
//! XDP session map, and registers itself here with
//! [`Session::set_ppp_backend`]; `ppp.active.*`, `ppp.why`, `ppp.history`
//! and the "drops N sessions" checks of the config commands read it.
//!
//! Every call is a copy of the service's state taken under its own lock,
//! never a wait on the network: the session lock is held while a command
//! runs, so the backend must answer from memory.

use std::sync::Arc;

use corerouter_model::MacAddr;
use corerouter_model::ppp::{ActiveSession, HOOK_VARS, HistoryEntry, ServiceStats, Why};
use serde_json::Value;

use crate::Session;

/// What the daemon's PPP service offers.
pub trait PppBackend: Send + Sync {
    /// The sessions up now (`/ppp active`).
    fn active(&self) -> Vec<ActiveSession>;
    /// Admin disconnect (LCP Terminate-Request, then PADT; Acct-Stop with
    /// Admin-Reset). Returns how many of `ids` were found.
    fn terminate(&self, ids: &[String]) -> usize;
    /// The last logins, failures and ends, oldest first.
    fn history(&self) -> Vec<HistoryEntry>;
    /// Where the logins of `name` (or of `mac`) get to.
    fn why(&self, name: Option<&str>, mac: Option<MacAddr>) -> Why;
    fn stats(&self) -> ServiceStats;
    /// The login of the session holding `ip` now (the identity chip).
    fn who(&self, ip: std::net::Ipv4Addr) -> Option<String> {
        let _ = ip;
        None
    }
    /// The login that held `ip` at Unix second `at` (CGNAT "Who was?"),
    /// from the history kept.
    fn who_at(&self, ip: std::net::Ipv4Addr, at: u64) -> Option<String> {
        let _ = (ip, at);
        None
    }
}

#[derive(Default)]
struct PppRuntime {
    backend: Option<Arc<dyn PppBackend>>,
}

impl Session {
    pub fn set_ppp_backend(&mut self, backend: Arc<dyn PppBackend>) {
        if let Some(rt) = self.ext_mut::<PppRuntime>() {
            rt.backend = Some(backend);
        }
    }

    /// The daemon's PPP service, if it runs one.
    pub fn ppp_backend(&self) -> Option<Arc<dyn PppBackend>> {
        self.ext::<PppRuntime>()?.backend.clone()
    }

    /// Active sessions now (empty without the service).
    pub fn ppp_active(&self) -> Vec<ActiveSession> {
        self.ppp_backend().map(|b| b.active()).unwrap_or_default()
    }
}

/// Replace the [`HOOK_VARS`] in the string values of `params`.
pub fn expand_hook(params: &serde_json::Map<String, Value>, vars: &[(&str, String)]) -> Value {
    let mut out = serde_json::Map::new();
    for (k, v) in params {
        let v = match v {
            Value::String(s) => {
                let mut t = s.clone();
                for (name, value) in vars {
                    if HOOK_VARS.contains(name) {
                        t = t.replace(name, value);
                    }
                }
                Value::String(t)
            }
            other => other.clone(),
        };
        out.insert(k.clone(), v);
    }
    Value::Object(out)
}

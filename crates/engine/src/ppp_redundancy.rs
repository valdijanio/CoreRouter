//! BNG redundancy (G4.3h) as the engine sees it. The daemon's `pppoe`
//! service runs the pair (the `proto-ha` role machine, the sync stream,
//! the access hellos) and registers itself here with
//! [`Session::set_ha_backend`]; `ppp.redundancy.monitor`, `switchover` and
//! `simulate-failure` go through it. Like [`crate::ppp::PppBackend`], every
//! call answers from memory: the session lock is held while a command runs.

use std::sync::Arc;

use corerouter_model::ppp_redundancy::{RedundancyStatus, TakeoverTest};

use crate::Session;

/// What the daemon's redundancy offers.
pub trait HaBackend: Send + Sync {
    fn status(&self) -> RedundancyStatus;
    /// Hand the active role to the standby peer (`force`: even with its
    /// replica incomplete). The error says why not, in English.
    fn switchover(&self, force: bool) -> Result<(), String>;
    /// "Simular falha": behave as a dead node for `secs`.
    fn simulate_failure(&self, secs: u32) -> Result<(), String>;
    /// "Testar tomada" (G3.6h): the checks, and with `run` the takeover
    /// itself (`method` `failure`: silent for `secs`, the peer detects it
    /// as a crash; `switchover`: planned handover). `force` runs it with a
    /// check failed.
    fn test_takeover(&self, method: &str, secs: u32, run: bool, force: bool) -> Result<TakeoverTest, String> {
        let _ = (method, secs, run, force);
        Err("this redundancy service cannot test a takeover".into())
    }
}

#[derive(Default)]
struct HaRuntime {
    backend: Option<Arc<dyn HaBackend>>,
}

impl Session {
    pub fn set_ha_backend(&mut self, backend: Arc<dyn HaBackend>) {
        if let Some(rt) = self.ext_mut::<HaRuntime>() {
            rt.backend = Some(backend);
        }
    }

    /// The redundancy of the daemon's PPP service, if it runs.
    pub fn ha_backend(&self) -> Option<Arc<dyn HaBackend>> {
        self.ext::<HaRuntime>()?.backend.clone()
    }
}

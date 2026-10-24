//! The RADIUS AAA service (G4.3j) as the engine sees it. The daemon's
//! `radius` service owns the sockets and the `proto-radius` client, and
//! registers itself here with [`Session::set_aaa_backend`]; commands
//! (`radius.monitor`, `radius.test`) and later callers (PPP G4.3d, IPoE
//! G4.3f, login) reach it through [`AaaBackend`].
//!
//! The API has no async and never blocks the caller: a request is queued and
//! its answer comes back through a callback, run on the service's thread.
//! Callbacks must be short and must not lock the session (the service may be
//! waiting for it to log); a caller that needs the session posts the answer
//! to its own thread.

use std::sync::Arc;

use corerouter_model::radius::{
    AcctCounters, AcctRequest, AuthReply, AuthRequest, CoaOutcome, CoaRequest, RadiusStatus,
};

use crate::Session;

/// Where an Access-Request's answer goes (Accept, Reject or Timeout with
/// the reply's attributes).
pub type AuthDone = Box<dyn FnOnce(AuthReply) + Send>;

/// Fresh counters of a running session, read when an Interim-Update is due.
/// `None`: the session is gone (no interim is sent and the schedule ends).
pub trait AcctSource: Send + Sync {
    fn counters(&self) -> Option<AcctCounters>;
}

/// The owner of subscriber sessions (PPP, IPoE): it applies a CoA or a
/// Disconnect to the sessions the selector names, all or none (RFC 5176
/// §3.6). Called on the service's thread: keep it short.
pub trait SessionOwner: Send + Sync {
    /// Short name for the log and `radius.incoming.get` (`ppp`).
    fn name(&self) -> &str;
    fn handle(&self, req: &CoaRequest) -> CoaOutcome;
}

/// What the daemon's AAA service offers.
pub trait AaaBackend: Send + Sync {
    /// Queue an Access-Request; `done` runs once with the answer.
    fn authenticate(&self, req: AuthRequest, done: AuthDone);

    /// Queue an Accounting-Request (retried until a server confirms it,
    /// RFC 5080 §2.2.1). A Start with `source` schedules the session's
    /// Interim-Updates (interval from the request or `ppp.aaa`, spread by
    /// `interim_jitter`); a Stop ends them. `Err`: not queued (no server
    /// for the service, accounting off, overload).
    fn account(
        &self,
        req: AcctRequest,
        source: Option<Arc<dyn AcctSource>>,
    ) -> Result<(), String>;

    /// Add an owner of sessions for CoA/Disconnect. Without one, every
    /// request gets a NAK with Error-Cause 503 (Session Context Not Found).
    fn register_owner(&self, owner: Arc<dyn SessionOwner>);

    /// `/radius monitor` and `/radius incoming` counters, now.
    fn status(&self) -> RadiusStatus;
}

#[derive(Default)]
struct AaaRuntime {
    backend: Option<Arc<dyn AaaBackend>>,
}

impl Session {
    pub fn set_aaa_backend(&mut self, backend: Arc<dyn AaaBackend>) {
        if let Some(rt) = self.ext_mut::<AaaRuntime>() {
            rt.backend = Some(backend);
        }
    }

    /// The daemon's AAA service, if it runs one.
    pub fn aaa_backend(&self) -> Option<Arc<dyn AaaBackend>> {
        self.ext::<AaaRuntime>()?.backend.clone()
    }
}
